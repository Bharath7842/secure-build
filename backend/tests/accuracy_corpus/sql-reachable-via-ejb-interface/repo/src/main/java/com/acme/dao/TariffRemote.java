package com.acme.dao;

import java.sql.ResultSet;
import javax.ejb.Remote;

@Remote
public interface TariffRemote {
    ResultSet legacyTariffs(String region) throws Exception;
}
