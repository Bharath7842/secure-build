package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

// #34 shape: legacy concatenation left in a comment above the fixed query.
public class CommentedConcat {
    public void run(Connection c, long id) throws Exception {
        // String sql = "SELECT * FROM orders WHERE id = " + id;
        PreparedStatement ps = c.prepareStatement(/* "... " + id */ "SELECT * FROM orders WHERE id = ?");
        ps.setLong(1, id);
        ps.executeQuery();
    }
}
