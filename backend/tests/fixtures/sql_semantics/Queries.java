package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Collections;
import java.util.List;

// One query shape per method; each statement line carries a `Q:` marker.
public class Queries {
    private static final String BASE = "SELECT a FROM t";
    private static final String MONTH_FMT = "YYYYMM";

    public void literal(Connection c) throws Exception {
        c.prepareStatement("SELECT a FROM t WHERE id = ?"); // Q:literal
    }

    public void constantBase(Connection c) throws Exception {
        c.prepareStatement(BASE + " WHERE x = ?"); // Q:constant-base
    }

    public void concatValue(Connection c, String id) throws Exception {
        c.prepareStatement("SELECT a FROM t WHERE id = " + id); // Q:concat-value
    }

    public void orderBy(Connection c, String col) throws Exception {
        c.prepareStatement("SELECT a FROM t ORDER BY " + col); // Q:order-by
    }

    public void placeholderLoop(Connection c, List<Long> ids) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT a FROM t WHERE id IN (");
        for (int i = 0; i < ids.size(); i++) {
            sb.append("?,");
        }
        sb.setLength(sb.length() - 1);
        sb.append(")");
        c.prepareStatement(sb.toString()); // Q:placeholder-loop
    }

    public void rawCsv(Connection c, String idsCsv) throws Exception {
        c.prepareStatement("SELECT a FROM t WHERE id IN (" + idsCsv + ")"); // Q:raw-csv
    }

    public void helper(Connection c) throws Exception {
        c.prepareStatement(BASE + " WHERE " + QueryHelper.getDefaultWhere()); // Q:helper
    }

    public void toChar(Connection c) throws Exception {
        c.prepareStatement("SELECT a FROM t WHERE TO_CHAR(?, 'YYYYMM') = ?"); // Q:to-char
    }

    public void format(Connection c) throws Exception {
        c.prepareStatement(String.format("SELECT a FROM t WHERE TO_CHAR(d, '%s') = ?", MONTH_FMT)); // Q:format
    }

    public void nCopies(Connection c, List<Long> ids) throws Exception {
        String marks = String.join(",", Collections.nCopies(ids.size(), "?"));
        c.prepareStatement("SELECT a FROM t WHERE id IN (" + marks + ")"); // Q:ncopies
    }

    public void localSingle(Connection c) throws Exception {
        String sql = "SELECT a FROM t WHERE k = ?";
        // sql = sql + " AND legacy = " + legacyId;
        c.prepareStatement(sql); // Q:local-single
    }

    public void appendsBranch(Connection c, String name, boolean active) throws Exception {
        String sql = "SELECT a FROM t WHERE 1 = 1";
        if (active) {
            sql += " AND active = 1";
        }
        sql += " AND name = '" + name + "'";
        c.prepareStatement(sql); // Q:appends-branch
    }

    public void numericConcat(Connection c, long id) throws Exception {
        c.prepareStatement("SELECT a FROM t WHERE id = " + id); // Q:numeric
    }

    public void otherConstant(Connection c) throws Exception {
        c.prepareStatement(Tables.ORDERS_SELECT + " WHERE id = ?"); // Q:other-constant
    }

    public void ternary(Connection c, boolean desc) throws Exception {
        c.prepareStatement("SELECT a FROM t ORDER BY a " + (desc ? "DESC" : "ASC")); // Q:ternary
    }

    public void builderHelper(Connection c, String region) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT a FROM t WHERE ");
        appendRegion(sb, region);
        c.prepareStatement(sb.toString()); // Q:builder-helper
    }

    private void appendRegion(StringBuilder sb, String region) {
        sb.append("region = ?");
    }
}
