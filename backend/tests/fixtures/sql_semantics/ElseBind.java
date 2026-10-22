package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class ElseBind {
    public void run(Connection c, boolean flag, String v) throws Exception {
        PreparedStatement ps = c.prepareStatement("DELETE FROM t WHERE v = ?");
        if (flag) {
            System.out.println("skip");
        } else {
            ps.setString(1, v);
        }
        ps.executeUpdate();
    }
}
