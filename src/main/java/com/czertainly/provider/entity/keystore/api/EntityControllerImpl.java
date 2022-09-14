package com.czertainly.provider.entity.keystore.api;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.connector.entity.EntityController;
import com.czertainly.api.model.common.attribute.AttributeDefinition;
import com.czertainly.api.model.common.attribute.RequestAttributeDto;
import com.czertainly.api.model.connector.entity.EntityInstanceDto;
import com.czertainly.api.model.connector.entity.EntityInstanceRequestDto;
import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;
import com.czertainly.provider.entity.keystore.service.EntityService;
import com.czertainly.provider.entity.keystore.service.LocationAttributeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class EntityControllerImpl implements EntityController {

    @Autowired
    public void setEntityService(EntityService entityService) {
        this.entityService = entityService;
    }
    @Autowired
    public void setLocationAttributeService(LocationAttributeService locationAttributeService) {
        this.locationAttributeService = locationAttributeService;
    }

    EntityService entityService;
    LocationAttributeService locationAttributeService;

    @Autowired
    LocationAttributeService locationAttributeService;

    @Override
    public List<EntityInstanceDto> listEntityInstances() {
        return entityService.listEntityInstances();
    }

    @Override
    public EntityInstanceDto getEntityInstance(String entityUuid) throws NotFoundException {
        return entityService.getEntityInstance(entityUuid).mapToDto();
    }

    @Override
    public EntityInstanceDto createEntityInstance(EntityInstanceRequestDto request) throws AlreadyExistException {
        return entityService.createEntityInstance(request);
    }

    @Override
    public EntityInstanceDto updateEntityInstance(String entityUuid, EntityInstanceRequestDto request) throws NotFoundException {
        return entityService.updateEntityInstance(entityUuid, request);
    }

    @Override
    public void removeEntityInstance(String entityUuid) throws NotFoundException {
        entityService.removeEntityInstance(entityUuid);
    }

    @Override
    public List<AttributeDefinition> listLocationAttributes(String entityUuid) throws NotFoundException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        return locationAttributeService.listLocationAttributes(entity);
    }

    @Override
    public void validateLocationAttributes(String entityUuid, List<RequestAttributeDto> attributes) throws ValidationException, NotFoundException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateLocationAttributes(entity, attributes);
    }
}
