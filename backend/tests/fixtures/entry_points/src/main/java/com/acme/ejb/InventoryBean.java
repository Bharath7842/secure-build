package com.acme.ejb;

public class InventoryBean implements InventoryRemote {
    public int count(String sku) {
        return sku.length();
    }
}
