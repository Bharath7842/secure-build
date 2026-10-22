package com.acme.util;

import java.util.Calendar;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CalendarLog {
    private static final Logger logger = LoggerFactory.getLogger(CalendarLog.class);

    public void started(Calendar cal) {
        logger.error("started: " + cal.toString());
    }
}
