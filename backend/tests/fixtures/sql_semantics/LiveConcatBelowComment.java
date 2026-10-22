package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

// A fixed query in a comment, live concatenation below it.
public class LiveConcatBelowComment {
    public void run(Connection c, String id) throws Exception {
        // PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE id = ?");
        PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE id = '" + id + "'");
        ps.executeQuery();
    }
}
