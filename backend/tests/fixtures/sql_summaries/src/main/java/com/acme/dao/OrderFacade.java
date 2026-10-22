package com.acme.dao;

import java.sql.ResultSet;

// #38 / #74 shape: a facade with one safe and one unsafe implementation.
public interface OrderFacade {
    ResultSet findByCustomer(String customer) throws Exception;
}
