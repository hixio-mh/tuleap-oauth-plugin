package io.jenkins.plugins.tuleap_oauth.checks;

import com.google.gson.Gson;
import io.jenkins.plugins.tuleap_oauth.model.AccessTokenRepresentation;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.commons.lang.StringUtils;

import javax.inject.Inject;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AccessTokenCheckerImpl implements AccessTokenChecker {

    private static Logger LOGGER = Logger.getLogger(AccessTokenChecker.class.getName());

    private static final String CONTENT_TYPE_HEADER_VALUE = "application/json;charset=UTF-8";
    private static final String PRAGMA_HEADER_VALUE = "no-cache";

    private static final String  ACCESS_TOKEN_TYPE = "bearer";

    private Gson gson;

    @Inject
    public AccessTokenCheckerImpl(Gson gson){
        this.gson = gson;
    }

    public boolean checkResponseHeader(Response response) {
        String contentType = response.header("Content-type");
        if (StringUtils.isBlank(contentType)) {
            LOGGER.log(Level.WARNING, "There is no content type");
            return false;
        }

        if (!contentType.equals(CONTENT_TYPE_HEADER_VALUE)) {
            LOGGER.log(Level.WARNING, "Bad content type");
            return false;
        }

        if (!response.cacheControl().noStore()) {
            LOGGER.log(Level.WARNING, "Bad cache policy");
            return false;
        }

        String pragma = response.header("Pragma");
        if (StringUtils.isBlank(pragma)) {
            LOGGER.log(Level.WARNING, "Pragma header missing");
            return false;
        }

        if (!pragma.equals(PRAGMA_HEADER_VALUE)) {
            LOGGER.log(Level.WARNING, "Bad pragma value");
            return false;
        }
        return true;
    }

    public boolean checkResponseBody(AccessTokenRepresentation accessTokenRepresentation) throws IOException {
        if (accessTokenRepresentation == null) {
            LOGGER.log(Level.WARNING, "There is no body");
            return false;
        }


        if (StringUtils.isBlank(accessTokenRepresentation.getAccessToken())) {
            LOGGER.log(Level.WARNING, "Access token missing");
            return false;
        }

        if (StringUtils.isBlank(accessTokenRepresentation.getTokenType())) {
            LOGGER.log(Level.WARNING, "Token type missing");
            return false;
        }

        if (!accessTokenRepresentation.getTokenType().equals(ACCESS_TOKEN_TYPE)) {
            LOGGER.log(Level.WARNING, "Bad token type returned");
            return false;
        }

        if (StringUtils.isBlank(accessTokenRepresentation.getExpiresIn())) {
            LOGGER.log(Level.WARNING, "No expiration date returned");
            return false;
        }

        if (StringUtils.isBlank(accessTokenRepresentation.getIdToken())) {
            LOGGER.log(Level.WARNING, "id token parameter is missing");
            return false;
        }

        return true;
    }
}
