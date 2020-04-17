package io.jenkins.plugins.tuleap_oauth.checks;

import com.google.gson.Gson;
import io.jenkins.plugins.tuleap_oauth.model.AccessTokenRepresentation;
import okhttp3.CacheControl;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class AccessTokenCheckerImplTest {

    private Gson gson;

    @Before
    public void setUp() {
        this.gson = mock(Gson.class);
    }

    @Test
    public void testResponseHeaderReturnsFalseWhenThereIsNoContentType() {
        Response response = mock(Response.class);
        when(response.header("Content-type")).thenReturn(null);
        verify(response, never()).cacheResponse();

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseHeader(response));
    }

    @Test
    public void testResponseHeaderReturnsFalseWhenBadContentType() {
        Response response = mock(Response.class);
        when(response.header("Content-type")).thenReturn("application/ogg");
        verify(response, never()).cacheResponse();

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseHeader(response));
    }

    @Test
    public void testResponseHeaderReturnsFalseWhenBadCacheValue() {
        Response response = mock(Response.class);
        when(response.header("Content-type")).thenReturn("application/json;charset=UTF-8");

        CacheControl cache = mock(CacheControl.class);
        when(response.cacheControl()).thenReturn(cache);
        when(cache.noStore()).thenReturn(false);

        verify(response, never()).header("Pragma");

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseHeader(response));
    }

    @Test
    public void testResponseHeaderReturnsFalseWhenPragmaHeaderIsMissing() {
        Response response = mock(Response.class);
        when(response.header("Content-type")).thenReturn("application/json;charset=UTF-8");

        CacheControl cache = mock(CacheControl.class);
        when(response.cacheControl()).thenReturn(cache);
        when(cache.noStore()).thenReturn(true);

        when(response.header("Pragma")).thenReturn(null);

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseHeader(response));
    }

    @Test
    public void testResponseHeaderReturnsFalseWhenBadPragmaValue() {
        Response response = mock(Response.class);
        when(response.header("Content-type")).thenReturn("application/json;charset=UTF-8");

        CacheControl cache = mock(CacheControl.class);
        when(response.cacheControl()).thenReturn(cache);
        when(cache.noStore()).thenReturn(true);

        when(response.header("Pragma")).thenReturn("issou");

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseHeader(response));
    }

    @Test
    public void testResponseHeaderReturnsTrueWhenAllChecksAreOk() {
        Response response = mock(Response.class);
        when(response.header("Content-type")).thenReturn("application/json;charset=UTF-8");

        CacheControl cache = mock(CacheControl.class);
        when(response.cacheControl()).thenReturn(cache);
        when(cache.noStore()).thenReturn(true);

        when(response.header("Pragma")).thenReturn("no-cache");

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertTrue(accessTokenChecker.checkResponseHeader(response));
    }

    @Test
    public void testResponseBodyReturnsFalseWhenThereIsNoBody() throws IOException {
        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseBody(null));
    }

    @Test
    public void testResponseBodyReturnsFalseWhenTheAccessTokenIsMissing() throws IOException {
        ResponseBody body = mock(ResponseBody.class);

        AccessTokenRepresentation representation = mock(AccessTokenRepresentation.class);
        when(representation.getAccessToken()).thenReturn(null);
        when(this.gson.fromJson(body.string(), AccessTokenRepresentation.class)).thenReturn(representation);

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseBody(representation));
    }

    @Test
    public void testResponseBodyReturnsFalseWhenTheTokenTypeIsMissing() throws IOException {
        ResponseBody body = mock(ResponseBody.class);

        AccessTokenRepresentation representation = mock(AccessTokenRepresentation.class);
        when(representation.getAccessToken()).thenReturn("vroom vroom");
        when(representation.getTokenType()).thenReturn(null);
        when(this.gson.fromJson(body.string(), AccessTokenRepresentation.class)).thenReturn(representation);

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseBody(representation));
    }

    @Test
    public void testResponseBodyReturnsFalseWhenBadTokenType() throws IOException {
        ResponseBody body = mock(ResponseBody.class);

        AccessTokenRepresentation representation = mock(AccessTokenRepresentation.class);
        when(representation.getAccessToken()).thenReturn("vroom vroom");
        when(representation.getTokenType()).thenReturn("mac");
        when(this.gson.fromJson(body.string(), AccessTokenRepresentation.class)).thenReturn(representation);

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseBody(representation));
    }

    @Test
    public void testResponseBodyReturnsFalseWhenTheExpirationDateIsMissing() throws IOException {
        ResponseBody body = mock(ResponseBody.class);

        AccessTokenRepresentation representation = mock(AccessTokenRepresentation.class);
        when(representation.getAccessToken()).thenReturn("vroom vroom");
        when(representation.getTokenType()).thenReturn("bearer");
        when(representation.getExpiresIn()).thenReturn(null);
        when(this.gson.fromJson(body.string(), AccessTokenRepresentation.class)).thenReturn(representation);

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertFalse(accessTokenChecker.checkResponseBody(representation));
    }

    @Test
    public void testResponseBodyReturnsTrueWhenAllChecksAreOk() throws IOException {
        ResponseBody body = mock(ResponseBody.class);

        AccessTokenRepresentation representation = mock(AccessTokenRepresentation.class);
        when(representation.getAccessToken()).thenReturn("vroom vroom");
        when(representation.getTokenType()).thenReturn("bearer");
        when(representation.getExpiresIn()).thenReturn("1202424");
        when(this.gson.fromJson(body.string(), AccessTokenRepresentation.class)).thenReturn(representation);

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl(this.gson);
        assertTrue(accessTokenChecker.checkResponseBody(representation));
    }
}
