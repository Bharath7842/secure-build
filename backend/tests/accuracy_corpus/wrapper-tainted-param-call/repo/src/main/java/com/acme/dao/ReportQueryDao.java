package com.acme.dao;

import org.springframework.jdbc.core.JdbcTemplate;

public class ReportQueryDao {
    private JdbcTemplate jdbc;

    public int purgeReports(String owner) {
        return jdbc.update(String.format("DELETE FROM reports WHERE owner = '%s'", owner));
    }
}
