package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class LegacyCustomerLookup implements CustomerLookup {
    private Connection connection;

    public ResultSet byName(String name) throws Exception {
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM customers WHERE name = '" + name + "'");
    }
}
