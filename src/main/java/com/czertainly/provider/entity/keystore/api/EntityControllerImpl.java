package com.czertainly.provider.entity.keystore.api;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.connector.entity.EntityController;
import com.czertainly.api.model.connector.entity.EntityInstanceDto;
import com.czertainly.api.model.connector.entity.EntityInstanceRequestDto;
import com.czertainly.provider.entity.keystore.service.EntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class EntityControllerImpl implements EntityController {

    @Autowired
    EntityService entityService;

    @Override
    public List<EntityInstanceDto> listEntityInstances() {
        return null;
    }

    @Override
    public EntityInstanceDto getEntityInstance(String entityUuid) throws NotFoundException {
        return null;
    }

    @Override
    public EntityInstanceDto createEntityInstance(EntityInstanceRequestDto request) throws AlreadyExistException {
        return entityService.createEntityInstance(request);
    }

    @Override
    public EntityInstanceDto updateEntityInstance(String entityUuid, EntityInstanceRequestDto request) throws NotFoundException {
        return null;
    }

    @Override
    public void removeEntityInstance(String entityUuid) throws NotFoundException {
        entityService.removeEntityInstance(entityUuid);
    }
}
