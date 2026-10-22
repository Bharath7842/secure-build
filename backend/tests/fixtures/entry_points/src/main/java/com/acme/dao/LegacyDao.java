package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class LegacyDao {
    private Connection connection;

    private ResultSet unusedQuery(String name) throws Exception {
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM t WHERE name = '" + name + "'");
    }

    private ResultSet usedQuery(String name) throws Exception {
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM t WHERE name = '" + name + "'");
    }

    private ResultSet initQuery(String name) throws Exception {
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM t WHERE name = '" + name + "'");
    }

    private final Object warm = initQuery("x");

    public ResultSet find(String name) throws Exception {
        return usedQuery(name);
    }
}
