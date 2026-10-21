package com.acme;

// Added later: nothing here changes what the methods do.


public class Orders {
    private static final Logger log = LoggerFactory.getLogger(Orders.class);



    /** Documentation added above the method. */
    public void first(String x) {
        log.info(x);
        log.info(x);
    }

    public void second(String x) {
        log.info(x);
    }
}
