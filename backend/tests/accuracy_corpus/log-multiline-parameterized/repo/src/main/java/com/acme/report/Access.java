package com.acme.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Access {
    private static final Logger log = LoggerFactory.getLogger(Access.class);

    public void record(javax.servlet.http.HttpServletRequest request, String user) {
        log.warn("{} {} {}",
                user,
                "denied",
                request.getRequestURI());
    }
}
