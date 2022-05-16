package com.czertainly.provider.entity.keystore.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.AttributeDefinition;
import com.czertainly.api.model.connector.entity.EntityInstanceDto;
import com.czertainly.api.model.connector.entity.EntityInstanceRequestDto;
import com.czertainly.api.model.core.credential.CredentialDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.provider.entity.keystore.AttributeConstants;
import com.czertainly.provider.entity.keystore.dao.EntityInstanceRepository;
import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;
import com.czertainly.provider.entity.keystore.service.AttributeService;
import com.czertainly.provider.entity.keystore.enums.AuthenticationType;
import com.czertainly.provider.entity.keystore.service.EntityService;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
public class EntityServiceImpl implements EntityService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public static final int SSH_PORT = 22;
    public static final int SSH_DEFAULT_TIMEOUT = 30;

    private static final Map<Long, ClientSession> sessionCache = new ConcurrentHashMap<>();

    @Autowired
    private EntityInstanceRepository entityInstanceRepository;

    @Autowired
    private AttributeService attributeService;

    @Autowired
    private SshClient sshClient;

    @Override
    public List<EntityInstanceDto> listEntityInstances() {
        List<EntityInstance> entities;
        entities = entityInstanceRepository.findAll();
        if (!entities.isEmpty()) {
            return entities
                    .stream().map(EntityInstance::mapToDto)
                    .collect(Collectors.toList());
        }
        return null;
    }

    @Override
    public EntityInstanceDto getEntityInstance(String entityUuid) throws NotFoundException {
        return entityInstanceRepository.findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstance.class, entityUuid))
                .mapToDto();
    }

    @Override
    public EntityInstanceDto createEntityInstance(EntityInstanceRequestDto request) throws AlreadyExistException {
        if (entityInstanceRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(EntityInstance.class, request.getName());
        }

        if (!attributeService.validateAttributes(
                request.getKind(), request.getAttributes())) {
            throw new ValidationException("Entity instance attributes validation failed.");
        }

        EntityInstance instance = new EntityInstance();
        instance.setName(request.getName());
        instance.setHost(AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_HOST, request.getAttributes()));
        instance.setAuthenticationType(
                AuthenticationType.valueOf(
                        AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_AUTH_TYPE, request.getAttributes())
                )
        );
        instance.setUuid(UUID.randomUUID().toString());
        CredentialDto credential = AttributeDefinitionUtils.getCredentialValue(AttributeConstants.ATTRIBUTE_CREDENTIAL, request.getAttributes());
        instance.setCredentialUuid(credential.getUuid());
        instance.setCredentialData(AttributeDefinitionUtils.serialize(AttributeDefinitionUtils.responseAttributeConverter(credential.getAttributes())));

        instance.setAttributes(AttributeDefinitionUtils.serialize(AttributeDefinitionUtils.mergeAttributes(attributeService.getAttributes(request.getKind()), request.getAttributes())));

        // now test the session based on the attributes
        ClientSession session;
        try {
            session = establishSession(instance);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new ValidationException(ValidationError.create(ExceptionUtils.getRootCauseMessage(e)));
        }

        entityInstanceRepository.save(instance);

        try {
            sessionCache.put(instance.getId(), session);
        } catch (Exception e) {
            logger.error("Fail to cache session between Entity {} and {} due to error {}", instance.getId(), instance.getHost(), e.getMessage(), e);
        }

        return instance.mapToDto();
    }

    @Override
    public EntityInstanceDto updateEntityInstance(String entityUuid, EntityInstanceRequestDto request) throws NotFoundException {
        EntityInstance instance = entityInstanceRepository
                .findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstance.class, entityUuid));

        if (!attributeService.validateAttributes(
                request.getKind(), request.getAttributes())) {
            throw new ValidationException("Entity instance attributes validation failed.");
        }

        instance.setName(request.getName());
        instance.setHost(AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_HOST, request.getAttributes()));
        instance.setAuthenticationType(AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_AUTH_TYPE, request.getAttributes()));
        CredentialDto credential = AttributeDefinitionUtils.getCredentialValue(AttributeConstants.ATTRIBUTE_CREDENTIAL, request.getAttributes());
        instance.setCredentialUuid(credential.getUuid());
        instance.setCredentialData(AttributeDefinitionUtils.serialize(AttributeDefinitionUtils.responseAttributeConverter(credential.getAttributes())));
        instance.setAttributes(AttributeDefinitionUtils.serialize(AttributeDefinitionUtils.mergeAttributes(attributeService.getAttributes(request.getKind()), request.getAttributes())));

        // now test the session based on the attributes
        ClientSession session;
        try {
            session = establishSession(instance);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new ValidationException(ValidationError.create(ExceptionUtils.getRootCauseMessage(e)));
        }

        entityInstanceRepository.save(instance);

        try {
            sessionCache.replace(instance.getId(), session);
        } catch (Exception e) {
            logger.error("Fail to cache session between Entity {} and {} due to error {}", instance.getId(), instance.getHost(), e.getMessage(), e);
        }

        return instance.mapToDto();
    }

    @Override
    public void removeEntityInstance(String entityUuid) throws NotFoundException {
        EntityInstance instance = entityInstanceRepository
                .findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstance.class, entityUuid));

        entityInstanceRepository.delete(instance);

        try {
            sessionCache.remove(instance.getId());
        } catch (Exception e) {
            logger.error("Fail to remove session between Entity {} and {} from cache due to error {}", instance.getId(), instance.getHost(), e.getMessage(), e);
        }
    }

    private ClientSession establishSession(EntityInstance instance) {
        logger.debug("Starting the SSH client for Entity with name " + instance.getName());

        String host = instance.getHost();

        List<AttributeDefinition> attributes = AttributeDefinitionUtils.deserialize(instance.getCredentialData());
        String username = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_USERNAME, attributes);
        if (instance.getAuthenticationType().equals(AuthenticationType.BASIC)) {
            String password = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_PASSWORD, attributes);
        } else if (instance.getAuthenticationType().equals(AuthenticationType.SSH)) {
            // TODO
        }

        try (ClientSession session = sshClient.connect(username, host, SSH_PORT)
                .verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS).getSession()) {

            session.addPasswordIdentity(AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_PASSWORD, attributes));
            session.auth().verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS);

            return session;

        } catch (IOException e) {
            // TODO
            e.printStackTrace();
            throw new IllegalStateException("Failed to initialize session.", e);
        }
    }

}
