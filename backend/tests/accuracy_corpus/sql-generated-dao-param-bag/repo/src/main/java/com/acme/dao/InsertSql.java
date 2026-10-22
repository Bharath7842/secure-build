package com.acme.dao;

public final class InsertSql {
    private InsertSql() {
    }

    public static String forTable(String table, String[] columns) {
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
