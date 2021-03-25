package com.deogicorgi.security.authenticate;

import com.deogicorgi.security.model.AbstractSecurityUser;
import com.deogicorgi.security.model.UserAuthenticationToken;

public interface AuthenticationService {

    AbstractSecurityUser authenticate(String account, String password);
    UserAuthenticationToken generateToken(AbstractSecurityUser abstractSecurityUser);
}
