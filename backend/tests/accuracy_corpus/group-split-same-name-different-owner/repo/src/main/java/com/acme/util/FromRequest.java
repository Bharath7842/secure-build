package com.acme.util;

public class FromRequest {
    private PortDao dao;

    public long lookup(String number) {
        return dao.getPortID(number);
    }
}
