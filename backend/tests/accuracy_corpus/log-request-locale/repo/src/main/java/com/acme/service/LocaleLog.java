package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LocaleLog {
    private static final Logger log = LoggerFactory.getLogger(LocaleLog.class);

    public void seen(javax.servlet.http.HttpServletRequest request) {
        log.info("locale {}", request.getLocale());
    }
}
