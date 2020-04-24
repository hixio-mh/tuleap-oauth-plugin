package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_oauth.model.UserInfoRepresentation;
import okhttp3.Response;
import org.apache.commons.lang.StringUtils;

import java.util.logging.Logger;

public class UserInfoCheckerImpl implements UserInfoChecker {

    private static final Logger LOGGER = Logger.getLogger(UserInfoChecker.class.getName());

    private static final String CONTENT_TYPE_HEADER_VALUE = "application/json;charset=utf-8";

    @Override
    public boolean checkHandshake(Response response) {
        if (response.handshake() == null) {
            LOGGER.warning("TLS is not used");
            return false;
        }
        return true;
    }

    @Override
    public boolean checkUserInfoResponseHeader(Response response) {
        String contentType = response.header("Content-type");
        if (StringUtils.isBlank(contentType)) {
            LOGGER.warning("There is no content type");
            return false;
        }

        if (!contentType.equals(CONTENT_TYPE_HEADER_VALUE)) {
            LOGGER.warning("Bad content type value");
            return false;
        }
        return true;
    }

    @Override
    public boolean checkUserInfoResponseBody(UserInfoRepresentation userInfoRepresentation, DecodedJWT idToken) {
        if (StringUtils.isBlank(userInfoRepresentation.getSub())) {
            LOGGER.warning("sub parameter is missing");
            return false;
        }

        if (!userInfoRepresentation.getSub().equals(idToken.getSubject())) {
            LOGGER.warning("Subject not expected");
            return false;
        }
        return true;
    }
}
