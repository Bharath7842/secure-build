package com.acme.util;

import org.springframework.jdbc.core.JdbcTemplate;

public class JobCleaner {
    private JdbcTemplate jdbc;

    public int deleteJob(String id) {
        return jdbc.update(String.format("DELETE FROM job WHERE id = '%s'", id));
    }
}
