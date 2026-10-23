package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JobRunner {
    private static final Logger log = LoggerFactory.getLogger(JobRunner.class);

    public void run() {
        try {
            start();
        } catch (JobException e) {
            log.warn("failed {}", e.getMessage());
        }
    }

    private void start() throws JobException {
        throw new JobException("cannot start");
    }
}
