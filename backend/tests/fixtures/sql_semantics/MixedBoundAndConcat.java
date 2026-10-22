package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

// One value bound, another concatenated into the same query.
public class MixedBoundAndConcat {
    public void run(Connection c, String a, String b) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE a = ? AND b = '" + b + "'");
        ps.setString(1, a);
        ps.executeQuery();
    }
}
