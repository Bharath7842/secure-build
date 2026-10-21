package com.acme;

public class Orders {
    private static final Logger log = LoggerFactory.getLogger(Orders.class);

    public void first(String x) {
        log.info(x);
        log.info(x);
    }

    public void second(String x) {
        log.info(x);
    }
}
