package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_api.client.authentication.UserInfo;
import org.apache.commons.lang.StringUtils;

import java.util.logging.Logger;

public class UserInfoCheckerImpl implements UserInfoChecker {

    private static final Logger LOGGER = Logger.getLogger(UserInfoChecker.class.getName());

    @Override
    public boolean checkUserInfoResponseBody(UserInfo userInfo, DecodedJWT idToken) {
        if (StringUtils.isBlank(userInfo.getSubject())) {
            LOGGER.warning("sub parameter is missing");
            return false;
        }

        if (!userInfo.getSubject().equals(idToken.getSubject())) {
            LOGGER.warning("Subject not expected");
            return false;
        }
        return true;
    }
}
