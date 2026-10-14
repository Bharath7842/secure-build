package com.acme.repo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class OrderDao {
    private Connection conn;
    private String dbPassword = "Sup3rS3cretDbPass!";

    public ResultSet findByName(String name) {
        try {
            Statement st = conn.createStatement();
            return st.executeQuery("SELECT * FROM orders WHERE name = '" + name + "'");
        } catch (Exception e) {
            return null;
        }
    }

    public ResultSet findById(long id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
        ps.setLong(1, id);
        return ps.executeQuery();
    }

    public void deleteById(long id) {
        try {
            PreparedStatement ps = conn.prepareStatement("DELETE FROM orders WHERE id = ?");
            ps.setLong(1, id);
            ps.executeUpdate();
        } catch (Exception e) {
            // ignored
        }
    }
}
