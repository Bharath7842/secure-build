package com.acme.util;

import org.springframework.jdbc.core.JdbcTemplate;

public class PortDao {
    private JdbcTemplate jdbc;

    public long getPortID(String number) {
        return jdbc.query(String.format("SELECT id FROM ports WHERE number = '%s'", number), (rs, i) -> rs.getLong(1)).size();
    }
}
