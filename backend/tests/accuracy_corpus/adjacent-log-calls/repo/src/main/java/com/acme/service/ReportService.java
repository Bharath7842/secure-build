package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ReportService {
    private static final Logger log = LoggerFactory.getLogger(ReportService.class);

    public void run(int count, Exception ex) {
        log.info("rows " + count);
        log.warn("failed {}", ex.getMessage());
    }
}
