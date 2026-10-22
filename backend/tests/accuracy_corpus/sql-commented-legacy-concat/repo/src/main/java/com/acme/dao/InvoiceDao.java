package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class InvoiceDao {
    private Connection connection;

    public ResultSet findInvoice(String invoiceNo) throws Exception {
        // String sql = "SELECT * FROM invoices WHERE invoice_no = '" + invoiceNo + "'";
        PreparedStatement stmt = connection.prepareStatement("SELECT * FROM invoices WHERE invoice_no = ?");
        stmt.setString(1, invoiceNo);
        return stmt.executeQuery();
    }
}
