package com.deogicorgi.security.authenticate;

import com.deogicorgi.security.model.AbstractSecurityUser;
import com.deogicorgi.security.model.UserAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Override
    public AbstractSecurityUser authenticate(String account, String password) {
        return null;
    }

    @Override
    public UserAuthenticationToken generateToken(AbstractSecurityUser abstractSecurityUser) {
        return null;
    }
}
