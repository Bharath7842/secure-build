package com.acme;

public class OrderDaoTest {
    void testQuery(java.sql.Statement st, String name) throws Exception {
        st.executeQuery("SELECT * FROM orders WHERE name = '" + name + "'");
    }
}
