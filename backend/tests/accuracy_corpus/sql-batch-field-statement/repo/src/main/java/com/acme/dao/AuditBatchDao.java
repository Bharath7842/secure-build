package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class AuditBatchDao {
    private Connection connection;
    private PreparedStatement insert;

    public void open() throws Exception {
        insert = connection.prepareStatement("INSERT INTO audit (actor, msg) VALUES (?, ?)");
    }

    public void add(String actor, String msg) throws Exception {
        insert.setString(1, actor);
        insert.setString(2, msg);
        insert.addBatch();
    }

    public int[] flush() throws Exception {
        return insert.executeBatch();
    }
}
