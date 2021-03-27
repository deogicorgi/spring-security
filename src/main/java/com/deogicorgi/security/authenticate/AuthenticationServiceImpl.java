package com.deogicorgi.security.authenticate;

import com.deogicorgi.security.model.User;
import com.deogicorgi.security.model.UserAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Override
    public User authenticate(String account, String password) {
        return null;
    }

    @Override
    public UserAuthenticationToken generateToken(User user) {
        return null;
    }
}
