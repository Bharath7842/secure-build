package com.acme.log;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Renamed {
    private static final Logger AUDIT = LogManager.getLogger(Renamed.class);

    void run(String pwd) {
        AUDIT.info(pwd);
    }
}
