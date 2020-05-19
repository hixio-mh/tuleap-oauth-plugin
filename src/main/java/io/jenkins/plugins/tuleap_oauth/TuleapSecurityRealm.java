package io.jenkins.plugins.tuleap_oauth;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.inject.Guice;
import com.google.inject.Inject;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.jenkins.plugins.tuleap_oauth.checks.AccessTokenChecker;
import io.jenkins.plugins.tuleap_oauth.checks.AuthorizationCodeChecker;
import io.jenkins.plugins.tuleap_oauth.checks.IDTokenChecker;
import io.jenkins.plugins.tuleap_oauth.checks.UserInfoChecker;
import io.jenkins.plugins.tuleap_oauth.exceptions.UserInfoRetrievalException;
import io.jenkins.plugins.tuleap_oauth.guice.TuleapOAuth2GuiceModule;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.helper.TuleapAuthorizationCodeUrlBuilder;
import io.jenkins.plugins.tuleap_oauth.model.AccessTokenRepresentation;
import io.jenkins.plugins.tuleap_oauth.model.UserInfoRepresentation;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import okhttp3.*;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.verb.POST;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

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


    public static final String AUTHORIZATION_ENDPOINT = "oauth2/authorize?";
    private static final String ACCESS_TOKEN_ENDPOINT = "oauth2/token";
    private static final String USER_INFO_ENDPOINT = "oauth2/userinfo";

    public static final String SCOPES = "read:project read:user_membership openid profile";
    public static final String CODE_CHALLENGE_METHOD = "S256";

    private AuthorizationCodeChecker authorizationCodeChecker;
    private PluginHelper pluginHelper;
    private AccessTokenChecker accessTokenChecker;
    private OkHttpClient httpClient;
    private Gson gson;
    private IDTokenChecker IDTokenChecker;
    private UserInfoChecker userInfoChecker;
    private TuleapAuthorizationCodeUrlBuilder authorizationCodeUrlBuilder;
    private TuleapAccessTokenStorage tuleapAccessTokenStorage;

    @DataBoundConstructor
    public TuleapSecurityRealm(String tuleapUri, String clientId, String clientSecret) {
        this.setTuleapUri(Util.fixEmptyAndTrim(tuleapUri));
        this.clientId = Util.fixEmptyAndTrim(clientId);
        this.setClientSecret(Util.fixEmptyAndTrim(clientSecret));
    }

    @Inject
    public void setAuthorizationCodeUrlBuilder(TuleapAuthorizationCodeUrlBuilder authorizationCodeUrlBuilder) {
        this.authorizationCodeUrlBuilder = authorizationCodeUrlBuilder;
    }

    @Inject
    public void setUserInfoChecker(UserInfoChecker userInfoChecker) {
        this.userInfoChecker = userInfoChecker;
    }

    @Inject
    public void setIDTokenChecker(IDTokenChecker IDTokenChecker) {
        this.IDTokenChecker = IDTokenChecker;
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
    public void setTuleapAccessTokenStorage(TuleapAccessTokenStorage tuleapAccessTokenStorage) {
        this.tuleapAccessTokenStorage = tuleapAccessTokenStorage;
    }

    @Inject
    public void setHttpClient(OkHttpClient httpClient) {
        this.httpClient = httpClient;
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
    public UserDetails loadUserByUsername(String username) {
        Authentication authenticatedUserAcegiToken = SecurityContextHolder.getContext().getAuthentication();

        if (authenticatedUserAcegiToken == null) {
            throw new UsernameNotFoundException("No access token found for user " + username);
        }

        if (!(authenticatedUserAcegiToken instanceof TuleapAuthenticationToken)) {
            throw new UserMayOrMayNotExistException("Unknown token type for user " + username);
        }

        AccessTokenRepresentation accessToken = this.gson.fromJson(
            this.tuleapAccessTokenStorage.retrieve(Objects.requireNonNull(User.getById(username, false))).getPlainText(),
            AccessTokenRepresentation.class
        );

        Request userInfoRequest = new Request.Builder()
            .url(this.tuleapUri + USER_INFO_ENDPOINT)
            .addHeader("Authorization", "Bearer " + accessToken.getAccessToken())
            .get()
            .build();

        UserInfoRepresentation userInfoRepresentation;
        try (Response userInfoResponse = this.httpClient.newCall(userInfoRequest).execute()) {
            ResponseBody body = this.getResponseBody(userInfoResponse);
            if (body == null) {
                throw new UserInfoRetrievalException();
            }

            if (!this.userInfoChecker.checkHandshake(userInfoResponse) ||
                !this.userInfoChecker.checkUserInfoResponseHeader(userInfoResponse)
            ) {
                throw new UserInfoRetrievalException();
            }

            userInfoRepresentation = this.gson.fromJson(body.string(), UserInfoRepresentation.class);

            if (!this.userInfoChecker.checkUserInfoResponseBody(userInfoRepresentation, JWT.decode(accessToken.getIdToken()))) {
                throw new UserInfoRetrievalException();
            }

        } catch (IOException | UserInfoRetrievalException exception) {
            throw new UsernameNotFoundException("Unable to retrieve info for user " + username);
        }

        return new TuleapUserDetails(
            userInfoRepresentation.getUsername(),
            authenticatedUserAcegiToken.getAuthorities()
        );
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
        final String authorizationCodeUri = this.authorizationCodeUrlBuilder.buildRedirectUrlAndStoreSessionAttribute(request, this.tuleapUri, this.clientId);
        return new HttpRedirect(authorizationCodeUri);
    }

    private void injectInstances() {
        if (this.pluginHelper == null ||
            this.authorizationCodeChecker == null ||
            this.accessTokenChecker == null ||
            this.gson == null ||
            this.IDTokenChecker == null ||
            this.authorizationCodeUrlBuilder == null ||
            this.tuleapAccessTokenStorage == null
        ) {
            Guice.createInjector(new TuleapOAuth2GuiceModule()).injectMembers(this);
        }
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE") // see https://github.com/spotbugs/spotbugs/issues/651
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

        this.IDTokenChecker.checkHeader(idToken);
        this.IDTokenChecker.checkPayloadAndSignature(idToken, jwks,this.tuleapUri,this.clientId,request);

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

        this.tuleapAccessTokenStorage.save(
            Objects.requireNonNull(User.current()),
            Secret.fromString(this.gson.toJson(accessTokenRepresentation))
        );

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

        @POST
        public FormValidation doCheckTuleapUri(@QueryParameter String tuleapUri) {
            final PluginHelper pluginHelper = Guice.createInjector(new TuleapOAuth2GuiceModule()).getInstance(PluginHelper.class);
            if (pluginHelper.isHttpsUrl(tuleapUri)) {
                return FormValidation.ok();
            }
            return FormValidation.error(Messages.TuleapSecurityRealmDescriptor_CheckUrl());
        }

        @POST
        public FormValidation doCheckClientId(@QueryParameter String clientId) {
            if (StringUtils.isBlank(clientId)) {
                return FormValidation.error(Messages.TuleapSecurityRealmDescriptor_CheckClientIdEmpty());
            }

            if (!clientId.matches("^(tlp-client-id-)\\d+$")) {
                return FormValidation.error(Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat());
            }
            return FormValidation.ok();
        }
    }
}
