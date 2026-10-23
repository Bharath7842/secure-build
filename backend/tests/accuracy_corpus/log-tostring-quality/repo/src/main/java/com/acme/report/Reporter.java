package com.acme.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Reporter {
    private static final Logger log = LoggerFactory.getLogger(Reporter.class);

    public void run(Runnable job) {
        try {
            job.run();
        } catch (RuntimeException ex) {
            log.error("report failed " + ex.toString());
        }
    }
}
