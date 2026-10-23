package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CodeLog {
    private static final Logger log = LoggerFactory.getLogger(CodeLog.class);

    public void report(Outcome outcome) {
        log.info("code {}", outcome.getResultCode());
    }
}
