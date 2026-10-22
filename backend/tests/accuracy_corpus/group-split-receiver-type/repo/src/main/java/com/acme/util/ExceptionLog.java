package com.acme.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExceptionLog {
    private static final Logger logger = LoggerFactory.getLogger(ExceptionLog.class);

    public void failed(Exception ex) {
        logger.error("failed: " + ex.toString());
    }
}
