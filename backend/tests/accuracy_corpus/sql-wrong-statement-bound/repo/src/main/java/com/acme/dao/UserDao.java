package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserDao {
    private Connection connection;

    public ResultSet find(String login) throws Exception {
        PreparedStatement check = connection.prepareStatement("SELECT 1 FROM users WHERE login = ?");
        check.setString(1, login);
        PreparedStatement query = connection.prepareStatement(
                "SELECT * FROM users WHERE login = '" + login + "'");
        return query.executeQuery();
    }
}
