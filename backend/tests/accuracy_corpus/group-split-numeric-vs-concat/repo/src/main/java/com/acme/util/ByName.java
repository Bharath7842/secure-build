package com.acme.util;

import java.sql.Statement;

public class ByName {
    public void load(Statement stmt, String name) throws Exception {
        stmt.executeQuery("SELECT * FROM report WHERE name = '" + name + "'");
    }
}
