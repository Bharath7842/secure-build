package com.acme.dao;

import com.acme.util.XmlPortMsg;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SoapPortDao {
    private Connection connection;

    public ResultSet findByMessage(XmlPortMsg xmlPortMsg) throws Exception {
        PreparedStatement ps = connection.prepareStatement(
                "SELECT * FROM ports WHERE port_id = '" + xmlPortMsg.getPortID() + "'");
        return ps.executeQuery();
    }
}
