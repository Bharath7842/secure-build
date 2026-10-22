package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

public class TicketDao {
    private Connection connection;

    public ResultSet findAll(List<Long> ids) throws Exception {
        PreparedStatement ps = connection.prepareStatement(
                "SELECT * FROM tickets WHERE id IN (" + InList.marks(ids.size()) + ")");
        for (int i = 0; i < ids.size(); i++) {
            ps.setLong(i + 1, ids.get(i));
        }
        return ps.executeQuery();
    }
}
