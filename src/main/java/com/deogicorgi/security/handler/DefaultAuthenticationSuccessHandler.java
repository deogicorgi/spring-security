package com.deogicorgi.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;

public class DefaultAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                        HttpServletResponse httpServletResponse, Authentication authentication)
            throws IOException, ServletException {
        httpServletResponse.setStatus(200);
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        if (authorities.toString().contains("ROLE_ADMIN")) {
            httpServletResponse.setHeader("role", "ROLE_ADMIN");
        } else if (authorities.toString().contains("ROLE_NOPRICED")) {
            httpServletResponse.setHeader("role", "ROLE_NOPRICED");
        }
    }
}
