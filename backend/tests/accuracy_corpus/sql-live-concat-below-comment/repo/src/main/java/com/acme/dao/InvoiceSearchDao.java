package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class InvoiceSearchDao {
    private Connection connection;

    public ResultSet search(String invoiceNo) throws Exception {
        // PreparedStatement stmt = connection.prepareStatement("SELECT * FROM invoices WHERE invoice_no = ?");
        PreparedStatement stmt = connection.prepareStatement(
                "SELECT * FROM invoices WHERE invoice_no = '" + invoiceNo + "'");
        return stmt.executeQuery();
    }
}
