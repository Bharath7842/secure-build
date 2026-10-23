package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JobLog {
    private static final Logger log = LoggerFactory.getLogger(JobLog.class);

    public void started(String raw) {
        int jobId = Integer.parseInt(raw);
        log.info("job " + jobId);
    }
}
