package com.acme.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OrderService {
    private static final Logger log = LoggerFactory.getLogger(OrderService.class);

    public void trace(long id) {
        log.debug("select * from orders where id = " + id);
    }
}
