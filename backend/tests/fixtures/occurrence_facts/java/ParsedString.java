package com.acme.dao;

import java.sql.Statement;

public class ParsedString {
    void lookup(Statement stmt, String s) throws Exception {
        Long n = Long.parseLong(s);
        stmt.executeQuery("SELECT * FROM t WHERE id = " + s);
        stmt.executeQuery("SELECT * FROM t WHERE id = " + n);
    }
}
