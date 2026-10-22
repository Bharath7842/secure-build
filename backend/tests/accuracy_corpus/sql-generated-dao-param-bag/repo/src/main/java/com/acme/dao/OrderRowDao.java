package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class OrderRowDao {
    private static final String[] COLUMNS = {"ORDER_ID", "STATUS", "AMOUNT"};
    private Connection connection;

    public int insert(Object[] values) throws Exception {
        PreparedStatement ps = connection.prepareStatement(InsertSql.forTable("ORDERS", COLUMNS));
        for (int i = 0; i < values.length; i++) {
            ps.setObject(i + 1, values[i]);
        }
        return ps.executeUpdate();
    }
}
