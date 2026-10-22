package com.acme.service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class OrderService {
    private Connection connection;

    public ResultSet find(String orderId) throws Exception {
        PreparedStatement stmt = connection.prepareStatement("SELECT * FROM orders WHERE id = ?");
        stmt.setString(1, orderId);
        return stmt.executeQuery();
    }
}
