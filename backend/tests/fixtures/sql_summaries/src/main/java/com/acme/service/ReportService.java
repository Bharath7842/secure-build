package com.acme.service;

import com.acme.dao.OrderFacade;
import com.acme.dao.ReportDao;
import com.acme.dao.SafeOrderDao;
import java.sql.Connection;

public class ReportService {
    private OrderFacade orders;
    private SafeOrderDao safeOrders;
    private ReportDao reports;
    private Connection connection;

    public Object viaFacade(String name) throws Exception {
        return orders.findByCustomer(name);
    }

    public Object viaSafe(String name) throws Exception {
        return safeOrders.findByCustomer(name);
    }

    public Object constantFilter() throws Exception {
        return reports.runWhere(connection, "status = 1");
    }

    public Object userFilter(String filter) throws Exception {
        return reports.runWhere(connection, filter);
    }

    public long total() {
        return reports.count();
    }
}
