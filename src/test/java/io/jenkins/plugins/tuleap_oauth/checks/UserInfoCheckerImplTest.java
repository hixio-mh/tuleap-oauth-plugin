package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_oauth.model.UserInfoRepresentation;
import okhttp3.Handshake;
import okhttp3.Response;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class UserInfoCheckerImplTest {

    @Test
    public void testItReturnsFalseIfTheConnectionDoesNotUseTLS() {
        Response response = mock(Response.class);
        when(response.handshake()).thenReturn(null);

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertFalse(userInfoChecker.checkHandshake(response));
    }

    @Test
    public void testItReturnsTrueIfTheConnectionUsesTLS() {
        Response response = mock(Response.class);
        Handshake handshake = mock(Handshake.class);
        when(response.handshake()).thenReturn(handshake);

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertTrue(userInfoChecker.checkHandshake(response));
    }

    @Test
    public void testItReturnsFalseWhenTheContentTypeIsMissing() {
        Response response = mock(Response.class);
        when(response.header("Content-type")).thenReturn(null);

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertFalse(userInfoChecker.checkUserInfoResponseHeader(response));
    }

    @Test
    public void testItReturnsFalseWhenTheContentTypeValueIsNotExpected() {
        Response response = mock(Response.class);
        when(response.header("Content-type")).thenReturn("multipart/form-data; boundary=something");

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertFalse(userInfoChecker.checkUserInfoResponseHeader(response));
    }

    @Test
    public void testItReturnsTrueWhenGoodContentType() {
        Response response = mock(Response.class);
        when(response.header("Content-type")).thenReturn("application/json");

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertTrue(userInfoChecker.checkUserInfoResponseHeader(response));
    }

    @Test
    public void testItReturnFalseWhenTheSubjectParameterIsMissing() {
        UserInfoRepresentation userInfoRepresentation = mock(UserInfoRepresentation.class);
        when(userInfoRepresentation.getSub()).thenReturn(null);

        DecodedJWT idToken = mock(DecodedJWT.class);
        verify(idToken, never()).getSignature();

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertFalse(userInfoChecker.checkUserInfoResponseBody(userInfoRepresentation, idToken));
    }

    @Test
    public void testItReturnFalseWhenTheSubjectValueIsNotExpected() {
        UserInfoRepresentation userInfoRepresentation = mock(UserInfoRepresentation.class);
        when(userInfoRepresentation.getSub()).thenReturn("123");

        DecodedJWT idToken = mock(DecodedJWT.class);
        when(idToken.getSubject()).thenReturn("1510");

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertFalse(userInfoChecker.checkUserInfoResponseBody(userInfoRepresentation, idToken));
    }

    @Test
    public void testItReturnTrueIfTheBodyIsOk() {
        UserInfoRepresentation userInfoRepresentation = mock(UserInfoRepresentation.class);
        when(userInfoRepresentation.getSub()).thenReturn("123");

        DecodedJWT idToken = mock(DecodedJWT.class);
        when(idToken.getSubject()).thenReturn("123");

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertTrue(userInfoChecker.checkUserInfoResponseBody(userInfoRepresentation, idToken));
    }
}
