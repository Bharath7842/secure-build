package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class ReportDao {
    private Connection connection;

    public ResultSet load(String name) throws Exception {
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(QueryBuilder.forReport(name));
    }
}
