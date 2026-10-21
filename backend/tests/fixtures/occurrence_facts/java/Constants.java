package com.acme.dao;

import java.math.BigDecimal;
import java.sql.Statement;

public class Constants {
    private static final String TABLE = "orders";
    private static final String QUERY = "SELECT * FROM " + TABLE;

    void run(Statement stmt, String name, BigDecimal price, BigDecimal parsed) throws Exception {
        final String local = "x";
        BigDecimal made = new BigDecimal("1.5");
        stmt.executeQuery(QUERY + local);
        stmt.executeQuery("a" + price);
        stmt.executeQuery("a" + made);
    }
}
