package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthService {
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public boolean login(String user, String password) {
        logger.info("login attempt user=" + user + " password=" + password);
        return verify(user, password);
    }

    private boolean verify(String user, String password) {
        return user != null && !user.isEmpty() && password != null;
    }
}
