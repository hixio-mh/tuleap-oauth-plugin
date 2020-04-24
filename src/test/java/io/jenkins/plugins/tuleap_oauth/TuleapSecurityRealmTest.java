package io.jenkins.plugins.tuleap_oauth;

import com.auth0.jwk.JwkException;
import com.google.gson.Gson;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.tuleap_oauth.checks.AccessTokenChecker;
import io.jenkins.plugins.tuleap_oauth.checks.AuthorizationCodeChecker;
import io.jenkins.plugins.tuleap_oauth.checks.JWTChecker;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelperImpl;
import io.jenkins.plugins.tuleap_oauth.helper.TuleapHttpRedirect;
import io.jenkins.plugins.tuleap_oauth.okhttp.OkHttpClientProvider;
import io.jenkins.plugins.tuleap_oauth.pkce.PKCECodeBuilder;
import jenkins.model.Jenkins;
import okhttp3.OkHttpClient;
import org.acegisecurity.Authentication;
import org.eclipse.jetty.client.HttpRequest;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class TuleapSecurityRealmTest {

    private PluginHelper pluginHelper;
    private AuthorizationCodeChecker authorizationCodeChecker;
    private AccessTokenChecker accessTokenChecker;
    private Gson gson;
    private JWTChecker jwtChecker;
    private OkHttpClient httpClient;
    private PKCECodeBuilder codeBuilder;

    private Jenkins jenkins;

//    @Rule
//    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Before
    public void setUp() {
        this.pluginHelper = mock(PluginHelperImpl.class);
        this.authorizationCodeChecker = mock(AuthorizationCodeChecker.class);
        this.accessTokenChecker = mock(AccessTokenChecker.class);
        this.gson = mock(Gson.class);
        this.jwtChecker = mock(JWTChecker.class);
        this.codeBuilder = mock(PKCECodeBuilder.class);
        this.httpClient = mock(OkHttpClient.class);

        this.jenkins = mock(Jenkins.class);
        when(pluginHelper.getJenkinsInstance()).thenReturn(jenkins);
    }

    private void injectMock(TuleapSecurityRealm securityRealm) {
        securityRealm.setPluginHelper(this.pluginHelper);
        securityRealm.setAuthorizationCodeChecker(this.authorizationCodeChecker);
        securityRealm.setAccessTokenChecker(this.accessTokenChecker);
        securityRealm.setGson(this.gson);
        securityRealm.setJwtChecker(this.jwtChecker);
        securityRealm.setHttpClient(this.httpClient);
        securityRealm.setCodeBuilder(this.codeBuilder);
    }

    @Test
    public void testAddDashAtTheEndOfTheTuleapUriWhenItIsMissing() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("https://jenkins.example.com", "", "");
        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getTuleapUri());
    }

    @Test
    public void testItDoesNotAddADashAtTheOfTheUriIfTheUriAlreadyEndWithIt() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("https://jenkins.example.com/", "", "");
        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getTuleapUri());
    }

    @Test
    public void testItShouldRedirectToClassicLogoutUrlWhenAnonymousUsersCanRead() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getContextPath()).thenReturn("https://jenkins.example.com");

        Authentication authentication = mock(Authentication.class);

        when(this.jenkins.hasPermission(Jenkins.READ)).thenReturn(true);

        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "", "");
        this.injectMock(tuleapSecurityRealm);

        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getPostLogOutUrl(request, authentication));
    }

    @Test
    public void testItShouldRedirectToTuleapLogoutUrlWhenAnonymousUsersCannotRead() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getContextPath()).thenReturn("https://jenkins.example.com");

        Authentication authentication = mock(Authentication.class);

        when(this.jenkins.hasPermission(Jenkins.READ)).thenReturn(false);

        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "", "");
        this.injectMock(tuleapSecurityRealm);

        assertEquals("https://jenkins.example.com/tuleapLogout", tuleapSecurityRealm.getPostLogOutUrl(request, authentication));
    }

//    @Test
//    public void testItShouldRedirectToTheErrorAuthenticationErrorPageWhenBadAuthorizationCode() throws JwkException, ServletException, IOException {
//        StaplerRequest request = mock(StaplerRequest.class);
//        StaplerResponse response = mock(StaplerResponse.class);
//
//        when(this.authorizationCodeChecker.checkAuthorizationCode(request)).thenReturn(false);
//
//        when(this.jenkins.getRootUrl()).thenReturn("https://jenkins.example.com/");
//
//        String expectedUri = "https://jenkins.example.com/tuleapError";
//        HttpResponse expectedRedirection;
//        expectedRedirection = new HttpRedirect(expectedUri);
//
//        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("","","");
//        this.injectMock(tuleapSecurityRealm);
//
//        System.out.println(expectedRedirection.hashCode());
//        HttpResponse response1;
//        response1 = new HttpRedirect(expectedUri);
////        System.out.println(HttpRedirect);
//        assertEquals(expectedRedirection.toString(), tuleapSecurityRealm.doFinishLogin(request,response).toString());
//    }

    @Test
    public void testItShouldReturnTheAuthorizationCodeUriWithTheRightParameters() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        StaplerRequest request = mock(StaplerRequest.class);

        String stateAndNonce = "Brabus";
        when(this.pluginHelper.buildRandomBase64EncodedURLSafeString()).thenReturn(stateAndNonce);

        HttpSession session = spy(HttpSession.class);
        when(request.getSession()).thenReturn(session);

        String rootUrl = "https://jenkins.example.com/";
        when(this.jenkins.getRootUrl()).thenReturn(rootUrl);

        String codeVerifier = "A35AMG";
        when(this.codeBuilder.buildCodeVerifier()).thenReturn(codeVerifier);
        when(this.codeBuilder.buildCodeChallenge(codeVerifier)).thenReturn("B35S");

        String clientId = "123";
        String tuleapUri = "https://tuleap.example.com/";

        String expectedUri = "https://tuleap.example.com/oauth2/authorize?" +
            "response_type=code" +
            "&client_id=123" +
            "&redirect_uri=" + URLEncoder.encode("https://jenkins.example.com/securityRealm/finishLogin", UTF_8.name()) +
            "&scope=read:project read:user_membership openid profile" +
            "&state=Brabus" +
            "&code_challenge=B35S" +
            "&code_challenge_method=S256" +
            "&nonce=Brabus";

        TuleapHttpRedirect expectedRedirection;
        expectedRedirection = new TuleapHttpRedirect(expectedUri);

        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm(tuleapUri, clientId, "");
        this.injectMock(tuleapSecurityRealm);
        TuleapHttpRedirect redirect = (TuleapHttpRedirect) tuleapSecurityRealm.doCommenceLogin(request);

        verify(session, times(1)).setAttribute(TuleapSecurityRealm.CODE_VERIFIER_SESSION_ATTRIBUTE, codeVerifier);
        verify(session, times(1)).setAttribute(TuleapSecurityRealm.NONCE_ATTRIBUTE, stateAndNonce);
        verify(session, times(1)).setAttribute(TuleapSecurityRealm.STATE_SESSION_ATTRIBUTE, stateAndNonce);

        assertEquals(expectedRedirection.getUrl(), redirect.getUrl());
    }
}
