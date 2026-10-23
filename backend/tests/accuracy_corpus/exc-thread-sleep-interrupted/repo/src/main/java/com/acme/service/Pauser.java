package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Pauser {
    private static final Logger log = LoggerFactory.getLogger(Pauser.class);

    public void pause() {
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            log.warn("failed {}", e.getMessage());
        }
    }
}
