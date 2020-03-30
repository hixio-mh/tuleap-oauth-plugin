package io.jenkins.plugins.tuleap_oauth;

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
import io.jenkins.plugins.tuleap_oauth.guice.TuleapOAuth2GuiceModule;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.pkce.PKCECodeBuilder;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import okhttp3.*;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;

import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.google.common.base.Charsets.UTF_8;

public class TuleapSecurityRealm extends SecurityRealm {

    private static Logger LOGGER = Logger.getLogger(TuleapSecurityRealm.class.getName());

    private String tuleapUri;
    private String clientId;
    private Secret clientSecret;

    private static final String LOGIN_URL = "securityRealm/commenceLogin";
    private static final String AUTHORIZATION_ENDPOINT = "oauth2/authorize?";

    public static final String CODE_VERIFIER_SESSION_ATTRIBUTE = "code_verifier";
    public static final String STATE_SESSION_ATTRIBUTE = "state";
    private static final String REDIRECT_URI = "securityRealm/finishLogin";

    private static final String ACCESS_TOKEN_ENDPOINT = "oauth2/token";

    public static final String SCOPE = "read:project";
    public static final String CODE_CHALLENGE_METHOD = "S256";

    private static final String URL_CHARACTERS_ALLOWED =  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

    private AuthorizationCodeChecker authorizationCodeChecker;
    private PluginHelper pluginHelper;
    private AccessTokenChecker accessTokenChecker;
    private OkHttpClient httpClient;
    private PKCECodeBuilder codeBuilder;

    @DataBoundConstructor
    public TuleapSecurityRealm(String tuleapUri, String clientId, String clientSecret) {
        this.setTuleapUri(Util.fixEmptyAndTrim(tuleapUri));
        this.clientId = Util.fixEmptyAndTrim(clientId);
        this.setClientSecret(Util.fixEmptyAndTrim(clientSecret));
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
                if (authentication instanceof UsernamePasswordAuthenticationToken) {
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

        final String state = this.buildStateRandomString();
        request.getSession().setAttribute(STATE_SESSION_ATTRIBUTE, state);

        final String rootUrl = this.getJenkinsInstance().getRootUrl();

        final String redirectUri = URLEncoder.encode(rootUrl + REDIRECT_URI, UTF_8.name());

        final String codeVerifier = this.codeBuilder.buildCodeVerifier();
        final String codeChallenge = this.codeBuilder.buildCodeChallenge(codeVerifier);
        request.getSession().setAttribute(CODE_VERIFIER_SESSION_ATTRIBUTE, codeVerifier);

        return new HttpRedirect(this.tuleapUri + AUTHORIZATION_ENDPOINT +
            "response_type=code" +
            "&client_id=" + this.clientId +
            "&redirect_uri=" + redirectUri +
            "&scope=" + SCOPE +
            "&state=" + state +
            "&code_challenge=" + codeChallenge +
            "&code_challenge_method="+ CODE_CHALLENGE_METHOD
        );
    }

    private void injectInstances() {
        if (this.pluginHelper == null ||
            this.authorizationCodeChecker == null ||
            this.accessTokenChecker == null
        ) {
            Guice.createInjector(new TuleapOAuth2GuiceModule()).injectMembers(this);
        }
    }

    private String buildStateRandomString() {
        final SecureRandom secureRandom = new SecureRandom();
        final StringBuilder stateStringBuilder = new StringBuilder();
        for (int i = 0; i < 30; i++) {
            stateStringBuilder.append(URL_CHARACTERS_ALLOWED.charAt(secureRandom.nextInt(URL_CHARACTERS_ALLOWED.length())));
        }
        return stateStringBuilder.toString();
    }

    public HttpResponse doFinishLogin(StaplerRequest request, StaplerResponse response) throws IOException {
        if (!this.authorizationCodeChecker.checkAuthorizationCode(request)) {
            return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
        }
        Request accessTokenRequest = this.getAccessTokenRequest(request);
        OkHttpClient okHttpClient = this.httpClient;

        try (Response accessTokenResponse = okHttpClient.newCall(accessTokenRequest).execute()) {
            ResponseBody body = accessTokenResponse.body();
            if (!accessTokenResponse.isSuccessful()) {
                if (body == null) {
                    LOGGER.log(Level.WARNING, "An error occurred");
                } else {
                    LOGGER.log(Level.WARNING, body.string());
                }
                return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
            }

            if (!this.accessTokenChecker.checkResponseHeader(accessTokenResponse)) {
                return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
            }

            if (!this.accessTokenChecker.checkResponseBody(body)) {
                return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
            }
        }

        this.authenticateAsAdmin(request);

        return HttpResponses.redirectToContextRoot();
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

    private void authenticateAsAdmin(StaplerRequest request) {
        User admin = User.getById("admin", true);
        if (admin == null) {
            throw new UsernameNotFoundException("Admin user cannot be retrieved...");
        }

        UserDetails adminDetails = admin.getUserDetailsForImpersonation();
        UsernamePasswordAuthenticationToken adminAuthToken = new UsernamePasswordAuthenticationToken(
            adminDetails.getUsername(),
            adminDetails.getPassword(),
            adminDetails.getAuthorities()
        );

        HttpSession session = request.getSession(false);
        if (session != null) {
            // avoid session fixation
            session.invalidate();
        }
        request.getSession(true);

        SecurityContextHolder.getContext().setAuthentication(adminAuthToken);
        SecurityListener.fireAuthenticated(adminDetails);
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getDisplayName() {
            return "Tuleap Authentication";
        }
    }
}
