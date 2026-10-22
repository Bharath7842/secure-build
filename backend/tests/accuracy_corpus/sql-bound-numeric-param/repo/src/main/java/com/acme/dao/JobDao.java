package com.acme.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;

public class JobDao {
    private Connection connection;

    public int deleteJob(long jobId) throws Exception {
        PreparedStatement stmt = connection.prepareStatement("DELETE FROM jobs WHERE job_id = ?");
        stmt.setLong(1, jobId);
        return stmt.executeUpdate();
    }
}
