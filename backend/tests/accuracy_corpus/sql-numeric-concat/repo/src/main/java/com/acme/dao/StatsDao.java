package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class StatsDao {
    private Connection connection;

    public ResultSet countForPort(long portId, int month) throws Exception {
        Statement stmt = connection.createStatement();
        return stmt.executeQuery("SELECT COUNT(*) FROM calls WHERE port_id = " + portId + " AND month = " + month);
    }
}
