package io.jenkins.plugins.tuleap_oauth;

import hudson.security.SecurityRealm;
import io.jenkins.plugins.tuleap_oauth.model.UserInfoRepresentation;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

import java.io.Serializable;

public class TuleapAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;
    private transient final UserInfoRepresentation userInfo;

    public TuleapAuthenticationToken(UserInfoRepresentation userInfo){
        super(new GrantedAuthority[] {SecurityRealm.AUTHENTICATED_AUTHORITY});

        this.userInfo = userInfo;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.userInfo.getUsername();
    }
}
