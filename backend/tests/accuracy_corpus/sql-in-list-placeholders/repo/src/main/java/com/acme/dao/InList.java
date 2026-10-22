package com.acme.dao;

public final class InList {
    private InList() {
    }

    public static String marks(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append("?,");
        }
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }
}
