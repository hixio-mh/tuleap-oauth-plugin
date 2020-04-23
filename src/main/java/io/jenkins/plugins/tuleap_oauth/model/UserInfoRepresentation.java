package io.jenkins.plugins.tuleap_oauth.model;

import com.google.gson.annotations.SerializedName;

public class UserInfoRepresentation {

    @SerializedName("sub")
    private String sub;

    @SerializedName("name")
    private String name;

    @SerializedName("preferred_username")
    private String username;

    @SerializedName("profile")
    private String profileUrl;

    @SerializedName("picture")
    private String picture;

    @SerializedName("zoneinfo")
    private String zoneInfo;

    @SerializedName("locale")
    private String locale;

    public String getSub() {
        return sub;
    }

    public String getName() {
        return name;
    }

    public String getUsername() {
        return username;
    }

    public String getProfileUrl() {
        return profileUrl;
    }

    public String getPicture() {
        return picture;
    }

    public String getZoneInfo() {
        return zoneInfo;
    }

    public String getLocale() {
        return locale;
    }
}
