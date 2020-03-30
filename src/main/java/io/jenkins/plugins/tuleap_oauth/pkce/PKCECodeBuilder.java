package io.jenkins.plugins.tuleap_oauth.pkce;

import java.security.NoSuchAlgorithmException;

public interface PKCECodeBuilder {
    String buildCodeVerifier();
    String buildCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException;
}
