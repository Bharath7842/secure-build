package com.acme.util;

import org.springframework.jdbc.core.JdbcTemplate;

public class PortDao implements PortApi {
    private JdbcTemplate jdbc;

    public boolean isPortable(String number) {
        return !jdbc.query(String.format("SELECT portable FROM ports WHERE number = '%s'", number), (rs, i) -> rs.getBoolean(1)).isEmpty();
    }
}
