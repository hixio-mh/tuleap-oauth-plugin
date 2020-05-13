package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_api.client.authentication.UserInfo;
import okhttp3.Response;

public interface UserInfoChecker {
    boolean checkUserInfoResponseBody(UserInfo userInfoRepresentation, DecodedJWT idToken);
}
