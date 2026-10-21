package com.acme.util;

public class PortService {
    private PortApi api;

    public boolean check(String number) {
        return api.isPortable(number);
    }
}
