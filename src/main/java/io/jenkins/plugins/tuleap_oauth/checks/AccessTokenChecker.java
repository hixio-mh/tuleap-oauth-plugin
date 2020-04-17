package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_oauth.model.AccessTokenRepresentation;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;

public interface AccessTokenChecker {
    boolean checkResponseHeader(Response response);
    boolean checkResponseBody(AccessTokenRepresentation accessTokenRepresentation) throws IOException;
}
