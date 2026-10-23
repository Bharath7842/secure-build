package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Auth {
    private static final Logger log = LoggerFactory.getLogger(Auth.class);

    public void login(String user, String password) {
        log.debug("login attempt user={} password={}", user, password);
    }
}
