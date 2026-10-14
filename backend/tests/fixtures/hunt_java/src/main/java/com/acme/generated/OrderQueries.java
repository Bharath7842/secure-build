// This file was automatically generated. DO NOT EDIT.
package com.acme.generated;

public class OrderQueries {
    public java.sql.ResultSet run(java.sql.Statement st, String v) throws Exception {
        return st.executeQuery("SELECT * FROM t WHERE v = '" + v + "'");
    }
}
