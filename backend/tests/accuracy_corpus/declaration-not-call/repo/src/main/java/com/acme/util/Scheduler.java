package com.acme.util;

public class Scheduler {
    private JobCleaner cleaner;

    public void nightly(int id) {
        cleaner.deleteJob(id);
    }
}
