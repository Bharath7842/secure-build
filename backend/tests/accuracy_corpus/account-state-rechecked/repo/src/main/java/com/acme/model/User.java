package com.acme.model;

public class User {
    private String username;
    private boolean locked;
    private int failedAttempts;

    public String getUsername() { return username; }
    public boolean isLocked() { return locked; }
    public void lock() { this.locked = true; }
    public int getFailedAttempts() { return failedAttempts; }
}
