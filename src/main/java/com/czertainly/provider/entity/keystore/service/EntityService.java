package com.czertainly.provider.entity.keystore.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.connector.entity.EntityInstanceDto;
import com.czertainly.api.model.connector.entity.EntityInstanceRequestDto;

public interface EntityService {

    EntityInstanceDto createEntityInstance(EntityInstanceRequestDto request) throws AlreadyExistException;

    void removeEntityInstance(String entityUuid) throws NotFoundException;
}
