package com.acme.util;

public class Banner {
    private AccountView view;

    public String title() {
        return "Welcome " + view.getAccountName();
    }
}
