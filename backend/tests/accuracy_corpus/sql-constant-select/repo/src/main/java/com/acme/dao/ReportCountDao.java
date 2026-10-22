package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class ReportCountDao {
    private static final String COUNT_DONE = "SELECT COUNT(*) FROM reports WHERE state = 'DONE'";
    private Connection connection;

    public ResultSet countDone() throws Exception {
        PreparedStatement stmt = connection.prepareStatement(COUNT_DONE);
        return stmt.executeQuery();
    }
}
