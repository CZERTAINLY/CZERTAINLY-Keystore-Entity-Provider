package com.czertainly.provider.entity.keystore.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.connector.entity.EntityInstanceDto;
import com.czertainly.api.model.connector.entity.EntityInstanceRequestDto;

import java.util.List;

public interface EntityService {

    List<EntityInstanceDto> listEntityInstances();

    EntityInstanceDto getEntityInstance(String entityUuid) throws NotFoundException;

    EntityInstanceDto createEntityInstance(EntityInstanceRequestDto request) throws AlreadyExistException;

    EntityInstanceDto updateEntityInstance(String entityUuid, EntityInstanceRequestDto request) throws NotFoundException;

    void removeEntityInstance(String entityUuid) throws NotFoundException;
}
