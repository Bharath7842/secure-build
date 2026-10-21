package com.acme.dao;

public class JobDao {
    public int deleteJob(int id) {
        return jdbc.update("DELETE FROM job WHERE id = ?", id);
    }

    void purge(int id) {
        deleteJob(id);
    }
}
