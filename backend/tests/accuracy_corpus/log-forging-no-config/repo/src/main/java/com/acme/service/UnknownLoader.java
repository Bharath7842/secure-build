package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UnknownLoader {
    private static final Logger log = LoggerFactory.getLogger(UnknownLoader.class);

    public void load(Runnable task) {
        try {
            task.run();
        } catch (RuntimeException ex) {
            log.warn("load failed: {}", ex.getMessage());
        }
    }
}
