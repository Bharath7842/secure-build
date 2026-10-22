package com.acme.dao;

// #73 shape: a generated insert builder fed column names and values separately.
public final class SqlGen {
    private SqlGen() {
    }

    public static String insert(String table, String[] columns) {
        StringBuilder sb = new StringBuilder("INSERT INTO ").append(table).append(" (");
        for (String column : columns) {
            sb.append(column).append(",");
        }
        sb.setLength(sb.length() - 1);
        sb.append(") VALUES (");
        for (String column : columns) {
            sb.append("?,");
        }
        sb.setLength(sb.length() - 1);
        return sb.append(")").toString();
    }
}
