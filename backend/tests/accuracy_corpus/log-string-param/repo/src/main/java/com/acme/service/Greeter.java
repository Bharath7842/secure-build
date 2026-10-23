package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Greeter {
    private static final Logger log = LoggerFactory.getLogger(Greeter.class);

    public void greet(String name) {
        log.info("hello " + name);
    }
}
