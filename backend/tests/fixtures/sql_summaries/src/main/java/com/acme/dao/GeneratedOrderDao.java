package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class GeneratedOrderDao {
    private static final String[] COLUMNS = {"ORDER_ID", "STATUS"};

    public int insert(Connection c, Object[] values) throws Exception {
        PreparedStatement ps = c.prepareStatement(SqlGen.insert("ORDERS", COLUMNS));
        for (int i = 0; i < values.length; i++) {
            ps.setObject(i + 1, values[i]);
        }
        return ps.executeUpdate();
    }

    public int insertInto(Connection c, String table, Object[] values) throws Exception {
        PreparedStatement ps = c.prepareStatement(SqlGen.insert(table, COLUMNS));
        for (int i = 0; i < values.length; i++) {
            ps.setObject(i + 1, values[i]);
        }
        return ps.executeUpdate();
    }
}
