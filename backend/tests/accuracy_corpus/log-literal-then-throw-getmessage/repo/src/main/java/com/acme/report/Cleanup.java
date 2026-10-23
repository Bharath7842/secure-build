package com.acme.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Cleanup {
    private static final Logger log = LoggerFactory.getLogger(Cleanup.class);

    public void purge(javax.servlet.http.HttpServletRequest request) {
        log.info("purge started");
        throw new IllegalStateException(request.getParameter("reason"));
    }
}
