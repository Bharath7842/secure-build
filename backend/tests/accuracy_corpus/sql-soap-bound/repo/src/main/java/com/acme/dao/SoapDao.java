package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SoapDao {
    private Connection connection;

    public ResultSet findOrder(String orderId) throws Exception {
        PreparedStatement stmt = connection.prepareStatement("SELECT * FROM orders WHERE id = ?");
        stmt.setString(1, orderId);
        return stmt.executeQuery();
    }
}
