package com.acme.util;

import com.acme.dao.PortDao;

public class PortLookup {
    private PortDao dao;

    public Object byNumber(long number) throws Exception {
        return dao.getPortID(number);
    }
}
