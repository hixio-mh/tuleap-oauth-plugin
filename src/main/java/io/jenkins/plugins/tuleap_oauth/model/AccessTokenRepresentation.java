package io.jenkins.plugins.tuleap_oauth.model;

import com.google.gson.annotations.SerializedName;

public class AccessTokenRepresentation {
    @SerializedName("access_token")
    private String accessToken;

    @SerializedName("token_type")
    private String tokenType;

    @SerializedName("expires_in")
    private String expiresIn;

    @SerializedName("id_token")
    private String idToken;

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getExpiresIn() {
        return expiresIn;
    }

    public String getIdToken() {
        return idToken;
    }
}
