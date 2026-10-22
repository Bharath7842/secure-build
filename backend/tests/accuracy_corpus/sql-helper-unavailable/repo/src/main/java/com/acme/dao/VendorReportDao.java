package com.acme.dao;

import com.vendor.sql.VendorSql;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class VendorReportDao {
    private Connection connection;

    public ResultSet run(String region) throws Exception {
        PreparedStatement ps = connection.prepareStatement(VendorSql.reportFor(region));
        return ps.executeQuery();
    }
}
