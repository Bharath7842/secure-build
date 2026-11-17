package com.acme.model;

public class Registration {
    public enum Status { PENDING, APPROVED, REJECTED }

    private Status status = Status.PENDING;

    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
}
