package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JobService {
    private static final Logger logger = LoggerFactory.getLogger(JobService.class);

    public void run(String msg, Exception ex) {
        logger.error(msg, ex);
    }
}
