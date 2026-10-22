package com.acme.dao;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

public class JdbcTemplateBound {
    private JdbcTemplate jdbcTemplate;
    private RowMapper<String> rowMapper;

    public Object find(long id) {
        return jdbcTemplate.query("SELECT name FROM t WHERE id = ?", rowMapper, id);
    }

    public Object all() {
        return jdbcTemplate.query("SELECT name FROM t", rowMapper);
    }
}
