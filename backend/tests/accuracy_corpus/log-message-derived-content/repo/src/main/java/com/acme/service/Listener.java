package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Listener {
    private static final Logger log = LoggerFactory.getLogger(Listener.class);

    public void onMessage(javax.jms.TextMessage message) throws Exception {
        log.info("received: " + message.getText());
    }
}
