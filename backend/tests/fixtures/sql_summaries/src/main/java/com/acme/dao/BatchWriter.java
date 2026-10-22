package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

// #45 / #46 shape: a field statement across methods, plus an unsafe overload.
public class BatchWriter {
    private Connection connection;
    private PreparedStatement insert;

    public void open() throws Exception {
        insert = connection.prepareStatement("INSERT INTO audit (msg) VALUES (?)");
    }

    public void add(String msg) throws Exception {
        insert.setString(1, msg);
        insert.addBatch();
    }

    public void add(String table, String msg) throws Exception {
        Statement st = connection.createStatement();
        st.executeUpdate("INSERT INTO " + table + " (msg) VALUES ('" + msg + "')");
    }

    public void flush() throws Exception {
        insert.executeBatch();
    }
}
