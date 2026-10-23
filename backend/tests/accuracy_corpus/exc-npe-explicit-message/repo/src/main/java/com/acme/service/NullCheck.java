package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NullCheck {
    private static final Logger log = LoggerFactory.getLogger(NullCheck.class);

    public void check(javax.servlet.http.HttpServletRequest request) {
        try {
            throw new NullPointerException(request.getParameter("n"));
        } catch (NullPointerException e) {
            log.warn("failed {}", e.getMessage());
        }
    }
}
