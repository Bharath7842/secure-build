package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class PortDao {
    private Connection connection;

    public ResultSet getPortID(long number) throws Exception {
        PreparedStatement ps = connection.prepareStatement("SELECT id FROM ports WHERE number = ?");
        ps.setLong(1, number);
        return ps.executeQuery();
    }
}
