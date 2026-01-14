package com.authcore.model;

import org.springframework.security.core.userdetails.UserDetails;

public abstract class AuthUser implements UserDetails {

    public abstract String getId();

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
}
