package com.acme.util;

public class Scheduler {
    private JobCleaner cleaner;

    public void nightly(String id) {
        cleaner.deleteJob(id);
    }
}
