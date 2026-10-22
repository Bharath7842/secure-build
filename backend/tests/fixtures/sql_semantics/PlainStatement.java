package com.acme.dao;

import java.sql.Connection;
import java.sql.Statement;

public class PlainStatement {
    public void run(Connection c, String name) throws Exception {
        Statement st = c.createStatement();
        st.executeQuery("SELECT * FROM t WHERE name = '" + name + "'");
    }
}
