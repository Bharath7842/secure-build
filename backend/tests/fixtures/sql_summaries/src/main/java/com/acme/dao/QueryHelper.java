package com.acme.dao;

import java.util.List;

// Query-building helpers, recognised by what they return, never by name.
public final class QueryHelper {
    public static final String ACTIVE = "status = 'ACTIVE'";

    private QueryHelper() {
    }

    public static String defaultWhere() {
        return ACTIVE + " AND deleted = 0";
    }

    public static String placeholders(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append("?,");
        }
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    public static String rawList(List<String> ids) {
        return String.join(",", ids);
    }

    public static void appendStatus(StringBuilder sb, String status) {
        sb.append("status = ?");
    }

    public static void appendOwner(StringBuilder sb, String owner) {
        sb.append("owner = '").append(owner).append("'");
    }
}
