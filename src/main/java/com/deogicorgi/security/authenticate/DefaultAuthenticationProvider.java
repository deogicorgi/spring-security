package com.deogicorgi.security.authenticate;

import com.deogicorgi.security.model.AbstractSecurityUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class DefaultAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationService authenticationService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String account = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        log.info("[{}] Start the authentication process. Request ID [{}]", getClass().getSimpleName(), account);

        AbstractSecurityUser abstractSecurityUser = authenticationService.authenticate(account, password);

        if (!abstractSecurityUser.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException("Credentials has expired.");
        }

        if (!abstractSecurityUser.isAccountNonExpired()) {
            throw new AccountExpiredException("Credentials has expired.");
        }

        if (!abstractSecurityUser.isAccountNonLocked()) {
            throw new LockedException("Credentials has expired.");
        }

        if (!abstractSecurityUser.isEnabled()) {
            throw new DisabledException("Credentials has expired.");
        }

        return authenticationService.generateToken(abstractSecurityUser);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
