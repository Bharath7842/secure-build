package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class ReportListDao {
    private Connection connection;

    public ResultSet list(String owner, String sortColumn) throws Exception {
        PreparedStatement stmt = connection.prepareStatement(
                "SELECT * FROM reports WHERE owner = ? ORDER BY " + sortColumn);
        stmt.setString(1, owner);
        return stmt.executeQuery();
    }
}
