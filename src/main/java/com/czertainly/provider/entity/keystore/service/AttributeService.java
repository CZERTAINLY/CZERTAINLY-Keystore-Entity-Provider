package com.czertainly.provider.entity.keystore.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.AttributeDefinition;
import com.czertainly.api.model.common.RequestAttributeDto;
import com.czertainly.api.model.connector.entity.EntityInstanceDto;

import java.util.List;

public interface AttributeService {

	List<AttributeDefinition> getAttributes(String kind);
	
	boolean validateAttributes(String kind, List<RequestAttributeDto> attributes);

	List<AttributeDefinition> listLocationAttributes(EntityInstanceDto entity);

	boolean validateLocationAttributes(EntityInstanceDto entity, List<RequestAttributeDto> attributes) throws ValidationException;
}
