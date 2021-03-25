package com.deogicorgi.security.model;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;


public abstract class AbstractSecurityUser implements UserDetails, CredentialsContainer {

    private final String account;
    private String password;

    private final Set<GrantedAuthority> authorities;
    private final boolean accountNonExpired;
    private final boolean accountNonLocked;
    private final boolean passwordNonExpired;
    private final boolean enabled;

    protected AbstractSecurityUser(String account, Set<GrantedAuthority> authorities, boolean accountNonExpired, boolean accountNonLocked, boolean passwordNonExpired, boolean enabled) {
        this.account = account;
        this.authorities = authorities;
        this.accountNonExpired = accountNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.passwordNonExpired = passwordNonExpired;
        this.enabled = enabled;
    }


    @Override
    public void eraseCredentials() {
        this.password = null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.account;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.passwordNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }
}
