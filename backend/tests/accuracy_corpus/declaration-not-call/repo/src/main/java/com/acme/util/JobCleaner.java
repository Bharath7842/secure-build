package com.acme.util;

import org.springframework.jdbc.core.JdbcTemplate;

public class JobCleaner {
    private JdbcTemplate jdbc;

    public int deleteJob(int id) {
        return jdbc.update("DELETE FROM job WHERE id = ?", id);
    }
}
