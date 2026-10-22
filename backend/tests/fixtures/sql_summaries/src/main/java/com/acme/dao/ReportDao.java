package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

public class ReportDao {
    public ResultSet listActive(Connection c) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM reports WHERE " + QueryHelper.defaultWhere());
        return ps.executeQuery();
    }

    public ResultSet findIn(Connection c, List<Long> ids) throws Exception {
        PreparedStatement ps = c.prepareStatement(
                "SELECT * FROM reports WHERE id IN (" + QueryHelper.placeholders(ids.size()) + ")");
        for (int i = 0; i < ids.size(); i++) {
            ps.setLong(i + 1, ids.get(i));
        }
        return ps.executeQuery();
    }

    public ResultSet findInRaw(Connection c, List<String> ids) throws Exception {
        PreparedStatement ps = c.prepareStatement(
                "SELECT * FROM reports WHERE id IN (" + QueryHelper.rawList(ids) + ")");
        return ps.executeQuery();
    }

    public ResultSet runWhere(Connection c, String where) throws Exception {
        Statement st = c.createStatement();
        return st.executeQuery("SELECT * FROM reports WHERE " + where);
    }

    public ResultSet byStatus(Connection c, String status) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT * FROM reports WHERE ");
        QueryHelper.appendStatus(sb, status);
        PreparedStatement ps = c.prepareStatement(sb.toString());
        ps.setString(1, status);
        return ps.executeQuery();
    }

    public ResultSet byOwner(Connection c, String owner) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT * FROM reports WHERE ");
        QueryHelper.appendOwner(sb, owner);
        PreparedStatement ps = c.prepareStatement(sb.toString());
        return ps.executeQuery();
    }

    public ResultSet walk(Connection c, int depth) throws Exception {
        if (depth > 0) {
            return walk(c, depth - 1);
        }
        PreparedStatement ps = c.prepareStatement("SELECT 1 FROM dual");
        return ps.executeQuery();
    }

    public ResultSet ping(Connection c, String q) throws Exception {
        return pong(c, q);
    }

    public ResultSet pong(Connection c, String q) throws Exception {
        return ping(c, q);
    }

    public ResultSet external(Connection c) throws Exception {
        PreparedStatement ps = c.prepareStatement(ExternalSql.build());
        return ps.executeQuery();
    }

    public long count() {
        return 0L;
    }
}
