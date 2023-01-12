package com.czertainly.provider.entity.keystore.service.impl;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.content.SecretAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.data.CredentialAttributeContentData;
import com.czertainly.api.model.connector.entity.EntityInstanceDto;
import com.czertainly.api.model.connector.entity.EntityInstanceRequestDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.provider.entity.keystore.AttributeConstants;
import com.czertainly.provider.entity.keystore.dao.EntityInstanceRepository;
import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;
import com.czertainly.provider.entity.keystore.enums.AuthenticationType;
import com.czertainly.provider.entity.keystore.service.AttributeService;
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

    public static final int SSH_PORT = 22;
    public static final int SSH_DEFAULT_TIMEOUT = 30;
    private static final Map<Long, ClientSession> sessionCache = new ConcurrentHashMap<>();
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private EntityInstanceRepository entityInstanceRepository;
    private AttributeService attributeService;
    private SshClient sshClient;

    @Autowired
    public void setEntityInstanceRepository(EntityInstanceRepository entityInstanceRepository) {
        this.entityInstanceRepository = entityInstanceRepository;
    }

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Autowired
    public void setSshClient(SshClient sshClient) {
        this.sshClient = sshClient;
    }

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
    public EntityInstance getEntityInstance(String entityUuid) throws NotFoundException {
        return entityInstanceRepository.findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstance.class, entityUuid));
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
        instance.setHost(AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_HOST, request.getAttributes(), StringAttributeContent.class).getData());
        instance.setAuthenticationType(
                AuthenticationType.findByCode(
                        AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_AUTH_TYPE, request.getAttributes(), StringAttributeContent.class).getData()
                )
        );
        instance.setUuid(UUID.randomUUID().toString());
        CredentialAttributeContentData credential = AttributeDefinitionUtils.getCredentialContent(AttributeConstants.ATTRIBUTE_CREDENTIAL, request.getAttributes());
        instance.setCredentialUuid(credential.getUuid());
        instance.setCredentialData(AttributeDefinitionUtils.serialize(credential.getAttributes()));

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
        instance.setHost(AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_HOST, request.getAttributes(), StringAttributeContent.class).getData());
        instance.setAuthenticationType(AuthenticationType.findByCode(AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_AUTH_TYPE, request.getAttributes(), StringAttributeContent.class).getData()));
        CredentialAttributeContentData credential = AttributeDefinitionUtils.getCredentialContent(AttributeConstants.ATTRIBUTE_CREDENTIAL, request.getAttributes());
        instance.setCredentialUuid(credential.getUuid());
        instance.setCredentialData(AttributeDefinitionUtils.serialize(credential.getAttributes()));
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

    @Override
    public ClientSession getSession(String entityUuid) throws NotFoundException {
        EntityInstance instance = entityInstanceRepository
                .findByUuid(entityUuid)
                .orElseThrow(() -> new NotFoundException(EntityInstance.class, entityUuid));
        return getSession(instance);
    }

    private synchronized ClientSession getSession(EntityInstance instance) {
        ClientSession session = sessionCache.get(instance.getId());
        if (session != null) {
            return session;
        }

        session = establishSession(instance);

        try {
            sessionCache.put(instance.getId(), session);
        } catch (Exception e) {
            logger.error("Fail to cache session between Entity {} and {} due to error {}", instance.getId(), instance.getHost(), e.getMessage(), e);
        }

        return session;
    }

    private ClientSession establishSession(EntityInstance instance) {
        logger.debug("Starting the SSH client for Entity with name " + instance.getName());

        String host = instance.getHost();

        List<BaseAttribute> attributes = AttributeDefinitionUtils.deserialize(instance.getCredentialData(), BaseAttribute.class);
        String username = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_USERNAME, attributes, StringAttributeContent.class).getData();
        String password = null;
        if (instance.getAuthenticationType().equals(AuthenticationType.BASIC)) {
            password = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_PASSWORD, attributes, SecretAttributeContent.class).getData().getSecret();
        }
        //else if (instance.getAuthenticationType().equals(AuthenticationType.SSH)) {
        // TODO
        //}

        try (ClientSession session = sshClient.connect(username, host, SSH_PORT)
                .verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS).getSession()) {

            session.addPasswordIdentity(password);
            session.auth().verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS);

            return session;

        } catch (IOException e) {
            // TODO
            logger.error(e.getMessage());
            throw new IllegalStateException("Failed to initialize session.", e);
        }
    }

}
