package com.acme.dao;

import java.sql.Statement;

public class CommentMatch {
    void run(Statement stmt, String s) throws Exception {
        /* stmt.executeQuery("SELECT " + s); */
        // stmt.executeQuery("DELETE " + s);
        stmt.executeQuery("SELECT 1");
    }
}
