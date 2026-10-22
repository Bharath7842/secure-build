package com.acme.util;

import org.springframework.jdbc.core.JdbcTemplate;

public class PortDao {
    private JdbcTemplate jdbc;

    public long getPortID(long number) {
        return jdbc.query("SELECT id FROM ports WHERE number = ?", (rs, i) -> rs.getLong(1), number).size();
    }
}
