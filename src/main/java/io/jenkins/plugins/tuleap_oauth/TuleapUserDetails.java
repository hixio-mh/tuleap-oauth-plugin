package io.jenkins.plugins.tuleap_oauth;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;

public class TuleapUserDetails extends User implements UserDetails {

    private String username;

    public TuleapUserDetails(String username, GrantedAuthority[] authorities) {
        super(username, "", true, true, true, true, authorities);
        this.username = username;
    }


    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object rhs) {
        return super.equals(rhs);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
