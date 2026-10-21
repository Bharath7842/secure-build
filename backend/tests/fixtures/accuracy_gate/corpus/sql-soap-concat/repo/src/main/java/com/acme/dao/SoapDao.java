package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SoapDao {
    private Connection connection;

    public ResultSet findOrder(String orderId) throws Exception {
        String sql = "SELECT * FROM orders WHERE id = '" + orderId + "'";
        PreparedStatement stmt = connection.prepareStatement(sql);
        return stmt.executeQuery();
    }
}
