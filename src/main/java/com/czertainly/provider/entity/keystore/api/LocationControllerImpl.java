package com.czertainly.provider.entity.keystore.api;

import com.czertainly.api.exception.LocationException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.interfaces.connector.entity.LocationController;
import com.czertainly.api.model.common.AttributeDefinition;
import com.czertainly.api.model.common.RequestAttributeDto;
import com.czertainly.api.model.connector.entity.*;
import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;
import com.czertainly.provider.entity.keystore.service.EntityService;
import com.czertainly.provider.entity.keystore.service.LocationAttributeService;
import com.czertainly.provider.entity.keystore.service.LocationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class LocationControllerImpl implements LocationController {

    @Autowired
    LocationService locationService;

    @Autowired
    EntityService entityService;

    @Autowired
    LocationAttributeService locationAttributeService;

    @Override
    public LocationDetailResponseDto getLocationDetail(String entityUuid, LocationDetailRequestDto request) throws NotFoundException, LocationException {
        return locationService.getLocationDetail(entityUuid, request);
    }

    @Override
    public PushCertificateResponseDto pushCertificateToLocation(String entityUuid, PushCertificateRequestDto request) throws NotFoundException, LocationException {
        return locationService.pushCertificateToLocation(entityUuid, request);
    }

    @Override
    public List<AttributeDefinition> listPushCertificateAttributes(String entityUuid) throws NotFoundException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        return locationAttributeService.listPushCertificateAttributes(entity);
    }

    @Override
    public void validatePushCertificateAttributes(String entityUuid, List<RequestAttributeDto> pushAttributes) throws NotFoundException, ValidationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validatePushCertificateAttributes(entity, pushAttributes);
    }

    @Override
    public RemoveCertificateResponseDto removeCertificateFromLocation(String entityUuid, RemoveCertificateRequestDto request) throws NotFoundException, LocationException {
        return locationService.removeCertificateFromLocation(entityUuid, request);
    }

    @Override
    public GenerateCsrResponseDto generateCsrLocation(String entityUuid, GenerateCsrRequestDto request) throws NotFoundException, LocationException {
        return locationService.generateCsrLocation(entityUuid, request);
    }

    @Override
    public List<AttributeDefinition> listGenerateCsrAttributes(String entityUuid) throws NotFoundException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        return locationAttributeService.listGenerateCsrAttributes(entity);
    }

    @Override
    public void validateGenerateCsrAttributes(String entityUuid, List<RequestAttributeDto> csrAttributes) throws NotFoundException, ValidationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateGenerateCsrAttributes(entity, csrAttributes);
    }
}