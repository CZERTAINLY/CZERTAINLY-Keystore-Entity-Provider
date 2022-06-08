package com.czertainly.provider.entity.keystore.service;

import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;

public interface SshService {

    String runRemoteCommand(String command, EntityInstance entity);

    void uploadFile(EntityInstance entity, String source, String destination);

    void downloadFile(EntityInstance entity, String remote, String local);
}
