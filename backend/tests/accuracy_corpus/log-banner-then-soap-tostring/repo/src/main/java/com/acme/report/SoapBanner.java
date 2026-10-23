package com.acme.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SoapBanner {
    private static final Logger log = LoggerFactory.getLogger(SoapBanner.class);

    public String call(javax.servlet.http.HttpServletRequest request) {
        log.info("Calling the SOAP service");
        return invoke(request.getParameter("id"));
    }

    private String invoke(String id) {
        return id;
    }
}
