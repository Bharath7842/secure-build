package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class CleanupDao {
    private Connection connection;

    public void purgeStale(ResultSet stale) throws Exception {
        while (stale.next()) {
            String owner = stale.getString("owner");
            Statement stmt = connection.createStatement();
            stmt.executeUpdate("DELETE FROM sessions WHERE owner = '" + owner + "'");
        }
    }
}
