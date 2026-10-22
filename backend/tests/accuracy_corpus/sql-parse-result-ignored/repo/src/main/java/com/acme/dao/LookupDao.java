package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class LookupDao {
    private Connection connection;

    public ResultSet find(String idText) throws Exception {
        long id = Long.parseLong(idText);
        Statement stmt = connection.createStatement();
        return stmt.executeQuery("SELECT * FROM lookups WHERE id = " + idText);
    }
}
