package com.acme.report;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class ReportB {
    private Connection connection;

    public ResultSet byId(int id) throws Exception {
        String sql = String.format("SELECT * FROM report_B WHERE id = %d", id);
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(sql);
    }
}
