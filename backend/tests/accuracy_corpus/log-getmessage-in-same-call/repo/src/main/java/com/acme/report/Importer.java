package com.acme.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Importer {
    private static final Logger log = LoggerFactory.getLogger(Importer.class);

    public void load(Runnable task) {
        try {
            task.run();
        } catch (RuntimeException ex) {
            log.warn("import failed: {}", ex.getMessage());
        }
    }
}
