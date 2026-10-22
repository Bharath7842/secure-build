package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class UnsafeOrderDao implements OrderFacade {
    private Connection connection;

    public ResultSet findByCustomer(String customer) throws Exception {
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM orders WHERE customer = '" + customer + "'");
    }
}
