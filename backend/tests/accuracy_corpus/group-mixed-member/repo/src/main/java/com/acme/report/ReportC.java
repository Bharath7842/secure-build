package com.acme.report;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class ReportC {
    private Connection connection;

    public ResultSet byName(String name) throws Exception {
        String sql = String.format("SELECT * FROM report_c WHERE name = '%s'", name);
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(sql);
    }
}
