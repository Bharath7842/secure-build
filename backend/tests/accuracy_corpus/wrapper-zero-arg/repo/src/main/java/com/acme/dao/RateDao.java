package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class RateDao {
    private Connection connection;

    public ResultSet loadAllRates() throws Exception {
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM rates");
    }
}
