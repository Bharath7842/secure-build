package com.acme.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogThrowable {
    private static final Logger log = LoggerFactory.getLogger(LogThrowable.class);

    void run() {
        try {
            work();
        } catch (Exception ex) {
            log.error("failed", ex);
        }
    }

    void work() {}
}
