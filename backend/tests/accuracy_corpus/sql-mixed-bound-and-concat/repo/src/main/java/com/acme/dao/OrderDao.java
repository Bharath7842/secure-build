package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class OrderDao {
    private Connection connection;

    public ResultSet find(String customer, String status) throws Exception {
        PreparedStatement stmt = connection.prepareStatement(
                "SELECT * FROM orders WHERE customer = ? AND status = '" + status + "'");
        stmt.setString(1, customer);
        return stmt.executeQuery();
    }
}
