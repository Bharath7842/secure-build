package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

// #47 shape: a constant query with nothing to bind.
public class ConstantSelect {
    private static final String COUNT = "SELECT COUNT(*) FROM jobs WHERE state = 'DONE'";

    public void run(Connection c) throws Exception {
        PreparedStatement ps = c.prepareStatement(COUNT);
        ps.executeQuery();
    }
}
