package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

// #54 shape: a PreparedStatement executed with its own SQL string.
public class ApiMisuse {
    private static final String COUNT_SQL = "SELECT COUNT(*) FROM orders";

    public void run(Connection c) throws Exception {
        PreparedStatement ps = c.prepareStatement(COUNT_SQL);
        ps.executeQuery(COUNT_SQL);
    }
}
