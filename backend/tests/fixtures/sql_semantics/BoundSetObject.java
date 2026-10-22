package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// #15 / #209 shape: a fixed query, one placeholder bound with setObject.
public class BoundSetObject {
    public ResultSet find(Connection c, Object id) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT name FROM accounts WHERE id = ?");
        ps.setObject(1, id);
        return ps.executeQuery();
    }
}
