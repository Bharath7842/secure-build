package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class AccountDao {
    private Connection connection;

    public ResultSet findAccount(Object accountId) throws Exception {
        PreparedStatement stmt = connection.prepareStatement(
                "SELECT name, TO_CHAR(opened, 'YYYYMM') FROM accounts WHERE id = ?");
        stmt.setObject(1, accountId);
        return stmt.executeQuery();
    }
}
