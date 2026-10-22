package com.acme.dao;

import java.sql.ResultSet;

public interface CustomerLookup {
    ResultSet byName(String name) throws Exception;
}
