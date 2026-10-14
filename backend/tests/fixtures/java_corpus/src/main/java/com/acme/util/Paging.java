package com.acme.util;

public class Paging {
    private final int[] items = new int[16];

    public int last(int count) {
        int index = count - 1;
        return items[index];
    }
}
