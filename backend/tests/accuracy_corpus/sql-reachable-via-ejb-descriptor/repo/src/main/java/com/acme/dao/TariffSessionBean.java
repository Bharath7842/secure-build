package com.acme.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class TariffSessionBean {
    private Connection connection;

    public ResultSet legacyTariffs(String region) throws Exception {
        Statement st = connection.createStatement();
        return st.executeQuery("SELECT * FROM tariffs WHERE region = '" + region + "'");
    }
}
