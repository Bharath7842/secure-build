package com.acme.service;

public class BackupService {
    public void archive(String directory) throws Exception {
        Runtime.getRuntime().exec("tar czf /backups/latest.tgz " + directory);
    }
}
