package com.czertainly.provider.entity.keystore.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.attribute.AttributeDefinition;
import com.czertainly.api.model.common.attribute.RequestAttributeDto;
import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;

import java.util.List;

public interface LocationAttributeService {

    List<AttributeDefinition> listLocationAttributes(EntityInstance entity);

    boolean validateLocationAttributes(EntityInstance entity, List<RequestAttributeDto> attributes) throws ValidationException;

    List<AttributeDefinition> listPushCertificateAttributes(EntityInstance entity) throws NotFoundException;

    boolean validatePushCertificateAttributes(EntityInstance entity, List<RequestAttributeDto> attributes) throws ValidationException;

    List<AttributeDefinition> listGenerateCsrAttributes(EntityInstance entity) throws NotFoundException;

    boolean validateGenerateCsrAttributes(EntityInstance entity, List<RequestAttributeDto> attributes) throws ValidationException;
}
