package com.deogicorgi.security.model;

import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

public class DefaultUser extends User {

    protected DefaultUser(String account, Set<GrantedAuthority> authorities, boolean accountNonExpired, boolean accountNonLocked, boolean passwordNonExpired, boolean enabled) {
        super(account, authorities, accountNonExpired, accountNonLocked, passwordNonExpired, enabled);
    }
}
