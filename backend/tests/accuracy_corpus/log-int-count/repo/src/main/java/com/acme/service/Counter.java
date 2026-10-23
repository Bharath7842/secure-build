package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Counter {
    private static final Logger log = LoggerFactory.getLogger(Counter.class);

    public void done(int count) {
        log.info("rows updated: " + count);
    }
}
