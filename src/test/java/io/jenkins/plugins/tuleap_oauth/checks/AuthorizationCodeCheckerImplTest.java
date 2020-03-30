package io.jenkins.plugins.tuleap_oauth.checks;

import org.junit.Test;
import org.kohsuke.stapler.StaplerRequest;

import javax.servlet.http.HttpSession;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class AuthorizationCodeCheckerImplTest {

    @Test
    public void testItReturnFalseWhenThereIsNoCodeReturned(){
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getParameter("code")).thenReturn("");
        verify(request,never()).getParameter("state");

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl();
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    public void testItReturnFalseWhenThereIsNoStateReturned(){
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("");
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn("");

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl();
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }
    @Test
    public void testItReturnFalseWhenThereIsNoStateStoredInSession(){
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("issou");
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn(null);

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl();
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    public void testItReturnFalseWhenTheStoredSessionStateAndTheReturnedStateAreDifferent() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("issou");
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn("naha");

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl();
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    public void testItReturnFalseWhenThereIsNoCodeVerifierStoredInSession() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("issou");
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn("issou");
        when(session.getAttribute("code_verifier")).thenReturn(null);

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl();
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    public void testItReturnTrueAuthorizationChecksAreOk() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("issou");
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn("issou");
        when(session.getAttribute("code_verifier")).thenReturn("tchiki tchiki");

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl();
        assertTrue(authorizationCodeChecker.checkAuthorizationCode(request));
    }
}
