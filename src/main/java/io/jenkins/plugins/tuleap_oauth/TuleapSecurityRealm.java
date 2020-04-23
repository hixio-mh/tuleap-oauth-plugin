package io.jenkins.plugins.tuleap_oauth;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.inject.Guice;
import com.google.inject.Inject;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import io.jenkins.plugins.tuleap_oauth.checks.AccessTokenChecker;
import io.jenkins.plugins.tuleap_oauth.checks.AuthorizationCodeChecker;
import io.jenkins.plugins.tuleap_oauth.checks.JWTChecker;
import io.jenkins.plugins.tuleap_oauth.checks.UserInfoChecker;
import io.jenkins.plugins.tuleap_oauth.guice.TuleapOAuth2GuiceModule;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.model.AccessTokenRepresentation;
import io.jenkins.plugins.tuleap_oauth.model.UserInfoRepresentation;
import io.jenkins.plugins.tuleap_oauth.pkce.PKCECodeBuilder;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import okhttp3.*;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;

public class TuleapSecurityRealm extends SecurityRealm {

    private static Logger LOGGER = Logger.getLogger(TuleapSecurityRealm.class.getName());

    private String tuleapUri;
    private String clientId;
    private Secret clientSecret;

    private static final String LOGIN_URL = "securityRealm/commenceLogin";
    public static final String REDIRECT_URI = "securityRealm/finishLogin";

    public static final String CODE_VERIFIER_SESSION_ATTRIBUTE = "code_verifier";
    public static final String STATE_SESSION_ATTRIBUTE = "state";
    public static final String JENKINS_REDIRECT_URI_ATTRIBUTE = "redirect_uri";
    public static final String NONCE_ATTRIBUTE = "nonce";


    private static final String AUTHORIZATION_ENDPOINT = "oauth2/authorize?";
    private static final String ACCESS_TOKEN_ENDPOINT = "oauth2/token";
    private static final String USER_INFO_ENDPOINT = "oauth2/userinfo";

    private static final String SCOPES = "read:project read:user_membership openid profile";
    public static final String CODE_CHALLENGE_METHOD = "S256";

    private AuthorizationCodeChecker authorizationCodeChecker;
    private PluginHelper pluginHelper;
    private AccessTokenChecker accessTokenChecker;
    private OkHttpClient httpClient;
    private PKCECodeBuilder codeBuilder;
    private Gson gson;
    private JWTChecker jwtChecker;
    private UserInfoChecker userInfoChecker;

    @DataBoundConstructor
    public TuleapSecurityRealm(String tuleapUri, String clientId, String clientSecret) {
        this.setTuleapUri(Util.fixEmptyAndTrim(tuleapUri));
        this.clientId = Util.fixEmptyAndTrim(clientId);
        this.setClientSecret(Util.fixEmptyAndTrim(clientSecret));
    }

    @Inject
    public void setUserInfoChecker(UserInfoChecker userInfoChecker) {
        this.userInfoChecker = userInfoChecker;
    }

    @Inject
    public void setJwtChecker(JWTChecker jwtChecker) {
        this.jwtChecker = jwtChecker;
    }

    @Inject
    public void setGson(Gson gson) {
        this.gson = gson;
    }

    @Inject
    public void setAuthorizationCodeChecker(AuthorizationCodeChecker authorizationCodeChecker) {
        this.authorizationCodeChecker = authorizationCodeChecker;
    }

    @Inject
    public void setPluginHelper(PluginHelper pluginHelper) {
        this.pluginHelper = pluginHelper;
    }

    @Inject
    public void setAccessTokenChecker(AccessTokenChecker accessTokenChecker) {
        this.accessTokenChecker = accessTokenChecker;
    }

    @Inject
    public void setHttpClient(OkHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Inject
    public void setCodeBuilder(PKCECodeBuilder codeBuilder) {
        this.codeBuilder = codeBuilder;
    }

    public String getTuleapUri() {
        return tuleapUri;
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    private void setTuleapUri(String tuleapUri) {
        if (!StringUtils.isBlank(tuleapUri) && !tuleapUri.endsWith("/")) {
            tuleapUri = tuleapUri.concat("/");
        }
        this.tuleapUri = tuleapUri;
    }

    private void setClientSecret(String secretString) {
        this.clientSecret = Secret.fromString(secretString);
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {

            public Authentication authenticate(Authentication authentication)
                throws AuthenticationException {
                if (authentication instanceof TuleapAuthenticationToken) {
                    return authentication;
                }
                throw new BadCredentialsException(
                    "Unexpected authentication type: " + authentication);
            }
        });
    }

    @Override
    public String getLoginUrl() {
        return LOGIN_URL;
    }

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        this.injectInstances();

        auth.setAuthenticated(false);
        Jenkins jenkins = this.getJenkinsInstance();
        if (jenkins.hasPermission(Jenkins.READ)) {
            return super.getPostLogOutUrl(req, auth);
        }
        return req.getContextPath() + "/" + TuleapLogoutAction.REDIRECT_ON_LOGOUT;
    }

    public HttpResponse doCommenceLogin(StaplerRequest request) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        this.injectInstances();

        final String state = this.pluginHelper.buildRandomBase64EncodedURLSafeString();
        request.getSession().setAttribute(STATE_SESSION_ATTRIBUTE, state);

        final String rootUrl = this.getJenkinsInstance().getRootUrl();

        final String redirectUri = URLEncoder.encode(rootUrl + REDIRECT_URI, UTF_8.name());
        final String codeVerifier = this.codeBuilder.buildCodeVerifier();
        final String codeChallenge = this.codeBuilder.buildCodeChallenge(codeVerifier);
        request.getSession().setAttribute(CODE_VERIFIER_SESSION_ATTRIBUTE, codeVerifier);

        request.getSession().setAttribute(JENKINS_REDIRECT_URI_ATTRIBUTE, this.pluginHelper.getJenkinsInstance().getRootUrl() + REDIRECT_URI);

        final String nonce = this.pluginHelper.buildRandomBase64EncodedURLSafeString();

        request.getSession().setAttribute(NONCE_ATTRIBUTE, nonce);

        return new HttpRedirect(this.tuleapUri + AUTHORIZATION_ENDPOINT +
            "response_type=code" +
            "&client_id=" + this.clientId +
            "&redirect_uri=" + redirectUri +
            "&scope=" + SCOPES +
            "&state=" + state +
            "&code_challenge=" + codeChallenge +
            "&code_challenge_method=" + CODE_CHALLENGE_METHOD +
            "&nonce=" + nonce
        );
    }

    private void injectInstances() {
        if (this.pluginHelper == null ||
            this.authorizationCodeChecker == null ||
            this.accessTokenChecker == null ||
            this.gson == null ||
            this.jwtChecker == null
        ) {
            Guice.createInjector(new TuleapOAuth2GuiceModule()).injectMembers(this);
        }
    }

    public HttpResponse doFinishLogin(StaplerRequest request, StaplerResponse response) throws IOException, JwkException, ServletException {
        if (!this.authorizationCodeChecker.checkAuthorizationCode(request)) {
            return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
        }

        Request accessTokenRequest = this.getAccessTokenRequest(request);
        OkHttpClient okHttpClient = this.httpClient;

        AccessTokenRepresentation accessTokenRepresentation;
        try (Response accessTokenResponse = okHttpClient.newCall(accessTokenRequest).execute()) {
            ResponseBody body = this.getResponseBody(accessTokenResponse);
            if (body == null) {
                return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
            }
            accessTokenRepresentation = this.gson.fromJson(body.string(), AccessTokenRepresentation.class);

            if (!this.accessTokenChecker.checkResponseHeader(accessTokenResponse)) {
                return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
            }

            if (!this.accessTokenChecker.checkResponseBody(accessTokenRepresentation)) {
                return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
            }
        }

        UrlJwkProvider provider = new UrlJwkProvider(new URL(this.tuleapUri + "oauth2/jwks"));
        List<Jwk> jwks = provider.getAll();
        DecodedJWT idToken = JWT.decode(accessTokenRepresentation.getIdToken());

        this.jwtChecker.checkHeader(idToken);
        this.jwtChecker.checkPayloadAndSignature(idToken, jwks,this.tuleapUri,this.clientId,request);

        Request req = new Request.Builder()
            .url(this.tuleapUri + USER_INFO_ENDPOINT)
            .addHeader("Authorization", "Bearer " + accessTokenRepresentation.getAccessToken())
            .get()
            .build();

        UserInfoRepresentation userInfoRepresentation;
        try (Response userInfoResponse = okHttpClient.newCall(req).execute()) {
            ResponseBody body = this.getResponseBody(userInfoResponse);
            if (body == null) {
                return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
            }

            if (!this.userInfoChecker.checkHandshake(userInfoResponse) ||
                !this.userInfoChecker.checkUserInfoResponseHeader(userInfoResponse)
            ) {
                return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
            }

            userInfoRepresentation = this.gson.fromJson(body.string(), UserInfoRepresentation.class);

            if (!this.userInfoChecker.checkUserInfoResponseBody(userInfoRepresentation, idToken)) {
                return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
            }
        }

        this.authenticateAsTuleapUser(request, userInfoRepresentation);

        return HttpResponses.redirectToContextRoot();
    }

    private ResponseBody getResponseBody(Response response) throws IOException {
        ResponseBody body = response.body();

        if (body == null) {
            LOGGER.log(Level.WARNING, "An error occurred");
            return null;
        }

        if (!response.isSuccessful()) {
            LOGGER.log(Level.WARNING, body.string());
            return null;
        }
        return body;
    }

    private Request getAccessTokenRequest(StaplerRequest request) {

        final String code = request.getParameter("code");
        final String codeVerifier = (String) request.getSession().getAttribute(CODE_VERIFIER_SESSION_ATTRIBUTE);
        RequestBody requestBody = new FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("code", code)
            .add("code_verifier", codeVerifier)
            .addEncoded("redirect_uri", this.pluginHelper.getJenkinsInstance().getRootUrl() + REDIRECT_URI)
            .build();

        return new Request.Builder()
            .url(this.tuleapUri + ACCESS_TOKEN_ENDPOINT)
            .addHeader("Authorization", Credentials.basic(this.clientId, this.clientSecret.getPlainText()))
            .addHeader("Content-Type", "application/x-www-form-urlencoded")
            .post(requestBody)
            .build();
    }

    private Jenkins getJenkinsInstance() {
        return this.pluginHelper.getJenkinsInstance();
    }

    private void authenticateAsTuleapUser(StaplerRequest request, UserInfoRepresentation userInfoRepresentation) {
        TuleapAuthenticationToken tuleapAuth = new TuleapAuthenticationToken(userInfoRepresentation);

        HttpSession session = request.getSession(false);
        if (session != null) {
            // avoid session fixation
            session.invalidate();
        }
        request.getSession(true);

        SecurityContextHolder.getContext().setAuthentication(tuleapAuth);
        User tuleapUser = User.current();
        if (tuleapUser == null) {
            throw new UsernameNotFoundException("User not found");
        }

        tuleapUser.setFullName(userInfoRepresentation.getUsername());
        SecurityListener.fireAuthenticated(new TuleapUserDetails(
            userInfoRepresentation.getUsername(),
            tuleapAuth.getAuthorities()));
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getDisplayName() {
            return "Tuleap Authentication";
        }
    }
}
