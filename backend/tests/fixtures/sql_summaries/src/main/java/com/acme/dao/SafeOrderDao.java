package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SafeOrderDao implements OrderFacade {
    private Connection connection;

    public ResultSet findByCustomer(String customer) throws Exception {
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM orders WHERE customer = ?");
        ps.setString(1, customer);
        return ps.executeQuery();
    }
}
