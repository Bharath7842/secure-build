package com.acme.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogCount {
    private static final Logger log = LoggerFactory.getLogger(LogCount.class);

    void report(int count) {
        log.info("rows " + count);
    }
}
