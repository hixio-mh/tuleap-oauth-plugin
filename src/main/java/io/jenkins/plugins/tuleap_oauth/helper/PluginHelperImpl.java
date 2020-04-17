package io.jenkins.plugins.tuleap_oauth.helper;

import jenkins.model.Jenkins;
import org.apache.commons.net.util.Base64;

import java.security.SecureRandom;

public class PluginHelperImpl implements PluginHelper {

    private final static Integer RECOMMENDED_LENGTH = 32;

    public Jenkins getJenkinsInstance() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins not started");
        }
        return jenkins;
    }

    public String buildRandomBase64EncodedURLSafeString() {
        byte[] code = new byte[RECOMMENDED_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(code);
        return Base64.encodeBase64URLSafeString(code);
    }
}
