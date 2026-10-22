package com.acme.util;

import com.acme.dao.RateDao;

public class RateCache {
    private RateDao dao;

    public Object refresh() throws Exception {
        return dao.loadAllRates();
    }
}
