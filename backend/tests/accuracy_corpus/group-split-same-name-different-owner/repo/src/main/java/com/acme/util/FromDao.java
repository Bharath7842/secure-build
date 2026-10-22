package com.acme.util;

public class FromDao {
    private PortDao dao;

    public long lookup() {
        return dao.getPortID("5");
    }
}
