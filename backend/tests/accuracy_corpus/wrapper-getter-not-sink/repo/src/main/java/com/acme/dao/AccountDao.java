package com.acme.dao;

import org.springframework.jdbc.core.JdbcTemplate;

public class AccountDao {
    private JdbcTemplate jdbc;

    public String getAccountName(String accountId) {
        return jdbc.query(String.format("SELECT name FROM accounts WHERE id = '%s'", accountId),
                (rs, i) -> rs.getString(1)).get(0);
    }
}
