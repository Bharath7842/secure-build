package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

// #36 / #66 shape: a numeric parameter visibly bound.
public class NumericBound {
    public void run(Connection c, long portId) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM ports WHERE port_id = ?");
        ps.setLong(1, portId);
        ps.executeQuery();
    }
}
