package com.deogicorgi.security.authenticate;

import com.deogicorgi.security.model.User;
import com.deogicorgi.security.model.UserAuthenticationToken;

public interface AuthenticationService {

    User authenticate(String account, String password);
    UserAuthenticationToken generateToken(User user);
}
