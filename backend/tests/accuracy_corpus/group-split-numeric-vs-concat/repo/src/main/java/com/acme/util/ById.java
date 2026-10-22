package com.acme.util;

import java.sql.Statement;

public class ById {
    public void load(Statement stmt, int id) throws Exception {
        stmt.executeQuery("SELECT * FROM report WHERE id = " + id);
    }
}
