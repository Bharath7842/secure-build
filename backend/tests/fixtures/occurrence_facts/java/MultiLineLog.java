package com.acme.log;

import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MultiLineLog {
    private static final Logger log = LoggerFactory.getLogger(MultiLineLog.class);

    void handle(HttpServletRequest req, Exception ex) {
        log.warn("{} {}",
            req.getRequestURI(),
            ex.getMessage());
    }
}
