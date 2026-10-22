package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

// #45 / #46 shape: a batch statement held in a field across methods.
public class FieldStatement {
    private PreparedStatement insert;

    public void open(Connection c) throws Exception {
        insert = c.prepareStatement("INSERT INTO log (msg) VALUES (?)");
    }

    public void add(String msg) throws Exception {
        insert.setString(1, msg);
        insert.addBatch();
    }

    public void flush() throws Exception {
        insert.executeBatch();
    }
}
