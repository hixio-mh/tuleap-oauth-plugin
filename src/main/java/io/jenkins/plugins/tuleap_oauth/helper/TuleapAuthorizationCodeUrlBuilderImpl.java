package io.jenkins.plugins.tuleap_oauth.helper;

import com.google.inject.Inject;
import io.jenkins.plugins.tuleap_oauth.pkce.PKCECodeBuilder;
import org.kohsuke.stapler.StaplerRequest;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;

import static io.jenkins.plugins.tuleap_oauth.TuleapSecurityRealm.*;
import static java.nio.charset.StandardCharsets.UTF_8;

public class TuleapAuthorizationCodeUrlBuilderImpl implements TuleapAuthorizationCodeUrlBuilder {

    private final PluginHelper pluginHelper;
    private final PKCECodeBuilder codeBuilder;

    @Inject
    public TuleapAuthorizationCodeUrlBuilderImpl(PluginHelper pluginHelper, PKCECodeBuilder codeBuilder) {
        this.pluginHelper = pluginHelper;
        this.codeBuilder = codeBuilder;
    }

    public String buildRedirectUrlAndStoreSessionAttribute(StaplerRequest request, String tuleapUri, String clientId) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        final String state = this.pluginHelper.buildRandomBase64EncodedURLSafeString();
        request.getSession().setAttribute(STATE_SESSION_ATTRIBUTE, state);

        final String rootUrl = this.pluginHelper.getJenkinsInstance().getRootUrl();

        final String redirectUri = URLEncoder.encode(rootUrl + REDIRECT_URI, UTF_8.name());
        final String codeVerifier = this.codeBuilder.buildCodeVerifier();
        final String codeChallenge = this.codeBuilder.buildCodeChallenge(codeVerifier);
        request.getSession().setAttribute(CODE_VERIFIER_SESSION_ATTRIBUTE, codeVerifier);

        final String nonce = this.pluginHelper.buildRandomBase64EncodedURLSafeString();
        request.getSession().setAttribute(NONCE_ATTRIBUTE, nonce);

        request.getSession().setAttribute(JENKINS_REDIRECT_URI_ATTRIBUTE, pluginHelper.getJenkinsInstance().getRootUrl() + REDIRECT_URI);

        return tuleapUri + AUTHORIZATION_ENDPOINT +
            "response_type=code" +
            "&client_id=" + clientId +
            "&redirect_uri=" + redirectUri +
            "&scope=" + SCOPES +
            "&state=" + state +
            "&code_challenge=" + codeChallenge +
            "&code_challenge_method=" + CODE_CHALLENGE_METHOD +
            "&nonce=" + nonce;
    }
}
