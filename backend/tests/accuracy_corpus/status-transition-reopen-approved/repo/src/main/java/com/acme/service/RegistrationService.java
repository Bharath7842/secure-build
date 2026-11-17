package com.acme.service;

import com.acme.model.Registration;
import com.acme.model.Registration.Status;

public class RegistrationService {
    public void approve(Registration registration) {
        if (registration.getStatus() != Status.PENDING) {
            throw new IllegalStateException("only a pending registration can be approved");
        }
        registration.setStatus(Status.APPROVED);
    }

    public void reject(Registration registration) {
        if (registration.getStatus() != Status.PENDING) {
            throw new IllegalStateException("only a pending registration can be rejected");
        }
        registration.setStatus(Status.REJECTED);
    }

    public void reopen(Registration registration) {
        registration.setStatus(Status.PENDING);
    }
}
