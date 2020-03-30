package io.jenkins.plugins.tuleap_oauth.pkce;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class PKCECodeBuilderImplTest {

    @Test
    public void testItShouldReturnARandomStringInBase64() {
        final PKCECodeBuilder codeBuilder = new PKCECodeBuilderImpl();
        final String result1 = codeBuilder.buildCodeVerifier();
        final String result2 = codeBuilder.buildCodeVerifier();

        assertTrue(Base64.isBase64(result1));
        assertTrue(Base64.isBase64(result2));
        assertNotEquals(result1, result2);
    }

    @Test
    public void testItShouldBuildCorrectChallenge() throws NoSuchAlgorithmException {
        final PKCECodeBuilder codeBuilder = new PKCECodeBuilderImpl();
        final String codeVerifier = "some code verifier";
        final String expectedChallenge = "m1GfpnTZ3GMybT0-zEFIFVtKZ5-__kYO0IxP_3lHoC4";

        assertEquals(expectedChallenge, codeBuilder.buildCodeChallenge(codeVerifier));
    }

}
