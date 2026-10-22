package com.acme.dao;

import java.util.List;

public final class CsvList {
    private CsvList() {
    }

    public static String join(List<String> values) {
        return String.join(",", values);
    }
}
