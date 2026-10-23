package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DescLog {
    private static final Logger log = LoggerFactory.getLogger(DescLog.class);

    public void report(Outcome outcome) {
        log.info("desc {}", outcome.getResultDesc());
    }
}
