package com.acme.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Counter {
    private static final Logger log = LoggerFactory.getLogger(Counter.class);

    public void run(int count, Exception ex) {
        log.info("rows " + count);
        log.warn("failed {}", ex.getMessage());
    }
}
