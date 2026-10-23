package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Console {
    private static final Logger log = LoggerFactory.getLogger(Console.class);

    public void login(String password) {
        System.out.println("password=" + password);
    }
}
