package com.acme.dao;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

// #4/#5 (numbers concatenated) and #53 (a stored string reused) shapes.
public class NumericAndStored {
    private String lastName;

    public void numericConcat(Connection c, long id) throws Exception {
        Statement st = c.createStatement();
        st.executeQuery("SELECT * FROM t WHERE id = " + id); // N:numeric
    }

    public void inlineParse(Connection c, String s) throws Exception {
        Statement st = c.createStatement();
        st.executeQuery("SELECT * FROM t WHERE id = " + Long.parseLong(s)); // N:inline-parse
    }

    public void parseIgnored(Connection c, String s) throws Exception {
        long n = Long.parseLong(s);
        Statement st = c.createStatement();
        st.executeQuery("SELECT * FROM t WHERE id = " + s); // N:parse-ignored
    }

    public void secondOrderString(Connection c, ResultSet rs) throws Exception {
        String name = rs.getString("name");
        Statement st = c.createStatement();
        st.executeUpdate("DELETE FROM t WHERE name = '" + name + "'"); // N:stored-string
    }

    public void secondOrderInline(Connection c, ResultSet rs) throws Exception {
        Statement st = c.createStatement();
        st.executeUpdate("DELETE FROM t WHERE name = '" + rs.getString(1) + "'"); // N:stored-inline
    }

    public void secondOrderField(Connection c, ResultSet rs) throws Exception {
        this.lastName = rs.getString("name");
        Statement st = c.createStatement();
        st.executeUpdate("DELETE FROM t WHERE name = '" + this.lastName + "'"); // N:stored-field
    }

    public void secondOrderNumeric(Connection c, ResultSet rs) throws Exception {
        long id = rs.getLong("id");
        Statement st = c.createStatement();
        st.executeUpdate("DELETE FROM t WHERE id = " + id); // N:stored-numeric
    }

    public void resultSetIntInline(Connection c, ResultSet rs) throws Exception {
        Statement st = c.createStatement();
        st.executeUpdate("DELETE FROM t WHERE id = " + rs.getInt(1)); // N:stored-int-inline
    }

    public void bigDecimal(Connection c, String s) throws Exception {
        BigDecimal amount = new BigDecimal(s);
        Statement st = c.createStatement();
        st.executeQuery("SELECT * FROM t WHERE amount > " + amount); // N:bigdecimal
    }
}
