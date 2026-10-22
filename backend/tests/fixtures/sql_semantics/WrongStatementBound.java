package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

// The bound statement is not the one that executes.
public class WrongStatementBound {
    public void run(Connection c, String id) throws Exception {
        PreparedStatement ps1 = c.prepareStatement("SELECT * FROM t WHERE id = ?");
        ps1.setString(1, id);
        PreparedStatement ps2 = c.prepareStatement("SELECT * FROM t WHERE id = '" + id + "'");
        ps2.executeQuery();
    }
}
