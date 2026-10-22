package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class BoundCustomerLookup implements CustomerLookup {
    private Connection connection;

    public ResultSet byName(String name) throws Exception {
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM customers WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }
}
