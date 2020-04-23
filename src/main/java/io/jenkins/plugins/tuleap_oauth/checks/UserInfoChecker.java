package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_oauth.model.UserInfoRepresentation;
import okhttp3.Response;

public interface UserInfoChecker {
    boolean checkHandshake(Response response);
    boolean checkUserInfoResponseHeader(Response response);
    boolean checkUserInfoResponseBody(UserInfoRepresentation userInfoRepresentation, DecodedJWT idToken);
}
