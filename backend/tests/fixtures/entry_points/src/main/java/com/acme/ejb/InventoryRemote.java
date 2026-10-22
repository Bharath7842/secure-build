package com.acme.ejb;

import javax.ejb.Remote;

@Remote
public interface InventoryRemote {
    int count(String sku);
}
