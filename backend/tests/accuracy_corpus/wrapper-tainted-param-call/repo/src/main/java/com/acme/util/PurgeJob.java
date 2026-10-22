package com.acme.util;

import com.acme.dao.ReportQueryDao;

public class PurgeJob {
    private ReportQueryDao dao;

    public int run(String requestedOwner) {
        return dao.purgeReports(requestedOwner);
    }

    public int nightly() {
        return dao.purgeReports("system");
    }
}
