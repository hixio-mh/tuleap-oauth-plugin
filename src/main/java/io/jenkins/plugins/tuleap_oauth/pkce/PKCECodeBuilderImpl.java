package io.jenkins.plugins.tuleap_oauth.pkce;

import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class PKCECodeBuilderImpl implements PKCECodeBuilder {

    @Override
    public String buildCodeVerifier() {
        byte[] code = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(code);
        return Base64.encodeBase64URLSafeString(code);
    }

    @Override
    public String buildCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
        byte[] codeVerifierBytesASCII = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(codeVerifierBytesASCII);
        byte[] digest = messageDigest.digest();
        return Base64.encodeBase64URLSafeString(digest);
    }
}
