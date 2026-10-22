package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class Reassigned {
    public void run(Connection c, String a, String b) throws Exception {
        PreparedStatement ps = c.prepareStatement("UPDATE t SET a = ? WHERE k = 1");
        ps.setString(1, a);
        ps.executeUpdate();
        ps = c.prepareStatement("UPDATE t SET b = ? WHERE k = 2");
        ps.setString(1, b);
        ps.executeUpdate();
    }
}
