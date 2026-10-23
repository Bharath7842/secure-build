package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JobEcho {
    private static final Logger log = LoggerFactory.getLogger(JobEcho.class);

    public void started(String raw) {
        int jobId = Integer.parseInt(raw);
        log.info("job " + raw);
    }
}
