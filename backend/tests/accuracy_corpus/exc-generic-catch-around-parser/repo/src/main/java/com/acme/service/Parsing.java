package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Parsing {
    private static final Logger log = LoggerFactory.getLogger(Parsing.class);

    public void parse(String raw) {
        try {
            Integer.parseInt(raw);
        } catch (Exception e) {
            log.warn("failed {}", e.getMessage());
        }
    }
}
