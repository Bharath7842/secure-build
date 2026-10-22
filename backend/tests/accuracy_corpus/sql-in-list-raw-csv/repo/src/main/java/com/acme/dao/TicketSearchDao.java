package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

public class TicketSearchDao {
    private Connection connection;

    public ResultSet findAll(List<String> ids) throws Exception {
        PreparedStatement ps = connection.prepareStatement(
                "SELECT * FROM tickets WHERE id IN (" + CsvList.join(ids) + ")");
        return ps.executeQuery();
    }
}
