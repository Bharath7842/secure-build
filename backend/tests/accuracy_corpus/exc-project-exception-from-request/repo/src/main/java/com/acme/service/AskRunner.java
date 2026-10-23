package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AskRunner {
    private static final Logger log = LoggerFactory.getLogger(AskRunner.class);

    public void run(javax.servlet.http.HttpServletRequest request) {
        try {
            ask(request);
        } catch (AskException e) {
            log.warn("failed {}", e.getMessage());
        }
    }

    private void ask(javax.servlet.http.HttpServletRequest request) throws AskException {
        throw new AskException(request.getParameter("why"));
    }
}
