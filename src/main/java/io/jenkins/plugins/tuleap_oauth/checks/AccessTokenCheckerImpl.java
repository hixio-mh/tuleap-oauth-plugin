package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import org.apache.commons.lang.StringUtils;

import java.util.logging.Level;
import java.util.logging.Logger;

public class AccessTokenCheckerImpl implements AccessTokenChecker {

    private static final Logger LOGGER = Logger.getLogger(AccessTokenChecker.class.getName());

    private static final String  ACCESS_TOKEN_TYPE = "bearer";

    @Override
    public boolean checkResponseBody(AccessToken accessToken){
        if (accessToken == null) {
            LOGGER.log(Level.WARNING, "There is no body");
            return false;
        }

        if (StringUtils.isBlank(accessToken.getAccessToken())) {
            LOGGER.log(Level.WARNING, "Access token missing");
            return false;
        }

        if (StringUtils.isBlank(accessToken.getTokenType())) {
            LOGGER.log(Level.WARNING, "Token type missing");
            return false;
        }

        if (!accessToken.getTokenType().equals(ACCESS_TOKEN_TYPE)) {
            LOGGER.log(Level.WARNING, "Bad token type returned");
            return false;
        }

        if (StringUtils.isBlank(accessToken.getExpiresIn())) {
            LOGGER.log(Level.WARNING, "No expiration date returned");
            return false;
        }

        if (StringUtils.isBlank(accessToken.getIdToken())) {
            LOGGER.log(Level.WARNING, "No id token returned");
            return false;
        }
        
        return true;
    }
}
