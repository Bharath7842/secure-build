package com.acme.util;

import org.springframework.jdbc.core.JdbcTemplate;

public class PortDao implements PortApi {
    private JdbcTemplate jdbc;

    public boolean isPortable(String number) {
        return !jdbc.query("SELECT portable FROM ports WHERE number = ?", (rs, i) -> rs.getBoolean(1), number).isEmpty();
    }
}
