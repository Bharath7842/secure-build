package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class CleanupByIdDao {
    private Connection connection;

    public void purgeStale(ResultSet stale) throws Exception {
        while (stale.next()) {
            long sessionId = stale.getLong("session_id");
            Statement stmt = connection.createStatement();
            stmt.executeUpdate("DELETE FROM sessions WHERE session_id = " + sessionId);
        }
    }
}
