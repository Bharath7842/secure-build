package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class PortDao {
    private Connection connection;

    public ResultSet findPort(String portIdFromSoap) throws Exception {
        PreparedStatement stmt = connection.prepareStatement(
                "SELECT * FROM ports WHERE port_id = '" + portIdFromSoap + "'");
        return stmt.executeQuery();
    }
}
