package com.acme.reflect;

public class Loader {
    public static void main(String[] args) throws Exception {
        Class.forName("com.acme.reflect.Plugin").getDeclaredConstructor().newInstance();
    }
}
