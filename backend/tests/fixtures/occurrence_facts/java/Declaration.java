package com.acme.dao;

public class Declaration {
    public int deleteJob(int id) {
        return remove(id) + 1;
    }

    boolean isReady() { return false; }

    int remove(int id) {
        return id;
    }

    void todo() {
        throw new UnsupportedOperationException("later");
    }
}
