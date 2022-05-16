package com.czertainly.provider.entity.keystore.service.impl;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.*;
import com.czertainly.api.model.connector.entity.EntityInstanceDto;
import com.czertainly.api.model.core.credential.CredentialDto;
import com.czertainly.provider.entity.keystore.AttributeConstants;
import com.czertainly.provider.entity.keystore.enums.KeystoreType;
import com.czertainly.provider.entity.keystore.service.AttributeService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.provider.entity.keystore.enums.AuthenticationType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.*;

@Service
@Transactional
public class AttributeServiceImpl implements AttributeService {
    private static final Logger logger = LoggerFactory.getLogger(AttributeServiceImpl.class);

    @Override
    public List<AttributeDefinition> getAttributes(String kind) {

        logger.info("Getting the Attributes for {}", kind);

        if (isKindSupported(kind)) {
            List<AttributeDefinition> attrs = new ArrayList<>();

            AttributeDefinition host = new AttributeDefinition();
            host.setUuid("5e9146a6-da8a-403f-99cb-d5d64d93ce1c");
            host.setName(AttributeConstants.ATTRIBUTE_HOST);
            host.setLabel(AttributeConstants.ATTRIBUTE_HOST_LABEL);
            host.setDescription("Hostname or IP address of the target system");
            host.setType(BaseAttributeDefinitionTypes.STRING);
            host.setRequired(true);
            host.setReadOnly(false);
            host.setVisible(true);
            attrs.add(host);

            AttributeDefinition authType = new AttributeDefinition();
            authType.setUuid("c6d5a3ef-bed6-49c6-ae51-2768026a8052");
            authType.setName(AttributeConstants.ATTRIBUTE_AUTH_TYPE);
            authType.setLabel(AttributeConstants.ATTRIBUTE_AUTH_TYPE_LABEL);
            authType.setDescription("Authentication type to create the Entity instance");
            authType.setType(BaseAttributeDefinitionTypes.LIST);
            authType.setRequired(true);
            authType.setReadOnly(false);
            authType.setVisible(true);
            authType.setValue(EnumSet.allOf(AuthenticationType.class));
            attrs.add(authType);

            AttributeDefinition credential = new AttributeDefinition();
            credential.setUuid("931073c0-0765-4e6d-904e-8b6364bb66ec");
            credential.setName(AttributeConstants.ATTRIBUTE_CREDENTIAL);
            credential.setLabel(AttributeConstants.ATTRIBUTE_CREDENTIAL_LABEL);
            credential.setDescription("Credential to authenticate to target server");
            credential.setType(BaseAttributeDefinitionTypes.CREDENTIAL);
            credential.setRequired(true);
            credential.setReadOnly(false);
            credential.setVisible(true);

            Set<AttributeCallbackMapping> mappings = new HashSet<>();
            mappings.add(new AttributeCallbackMapping(
                    "credentialKind",
                    AttributeValueTarget.PATH_VARIABLE,
                    authType.getValue()));

            AttributeCallback listCredentialCallback = new AttributeCallback();
            listCredentialCallback.setCallbackContext("core/getCredentials");
            listCredentialCallback.setCallbackMethod("GET");
            listCredentialCallback.setMappings(mappings);
            credential.setAttributeCallback(listCredentialCallback);

            attrs.add(credential);

            return attrs;
        } else {
            logger.info("Unsupported kind {}", kind);
            throw new IllegalStateException("Unsupported kind " + kind);
        }
    }

    @Override
    public boolean validateAttributes(String kind, List<RequestAttributeDto> attributes) {
        if (attributes == null) {
            return false;
        }

        AttributeDefinitionUtils.validateAttributes(getAttributes(kind), attributes);

        CredentialDto credential = AttributeDefinitionUtils.getCredentialValue(AttributeConstants.ATTRIBUTE_CREDENTIAL, attributes);
        if (!isCredentialSupported(credential)) {
            logger.debug("Unsupported authentication type {}", credential.getKind());
            throw new ValidationException("Unsupported authentication type " + credential.getKind());
        }

        return true;
    }

    @Override
    public List<AttributeDefinition> listLocationAttributes(EntityInstanceDto entity) {
        logger.info("Getting the Attributes for Location of Entity {} with UUID {}", entity.getName(), entity.getUuid());

        List<AttributeDefinition> attrs = new ArrayList<>();
        attrs.add(buildKeystorePathAttribute());
        attrs.add(buildKeystorePasswordAttribute());
        attrs.add(buildKeystoreTypeAttribute());

        return attrs;
    }

    @Override
    public boolean validateLocationAttributes(EntityInstanceDto entity, List<RequestAttributeDto> attributes) throws ValidationException {
        AttributeDefinitionUtils.validateAttributes(listLocationAttributes(entity), attributes);

        String keystoreType = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, attributes);

        if (!isKeystoreTypeSupported(keystoreType)) {
            logger.debug("Unsupported Keystore type {}", keystoreType);
            throw new ValidationException("Unsupported Keystore type " + keystoreType);
        }

        return true;
    }

    private boolean isKindSupported(String kind) {
        return kind.equals("Keystore");
    }

    private boolean isCredentialSupported(CredentialDto credential) {
        if (credential.getKind().equals("Basic")) {
            return true;
        }

        for (AuthenticationType c : AuthenticationType.values()) {
            if (c.name().equals(credential.getKind())) {
                return true;
            }
        }
        return false;
    }

    private boolean isKeystoreTypeSupported(String keystoreType) {
        for (KeystoreType c : KeystoreType.values()) {
            if (c.name().equals(keystoreType)) {
                return true;
            }
        }
        return false;
    }

    private AttributeDefinition buildKeystorePathAttribute() {
        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("12f55fa9-49a3-4afe-906b-ad48c76641ce");
        attribute.setName(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH_LABEL);
        attribute.setType(BaseAttributeDefinitionTypes.STRING);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setDescription("Full path to the Keystore located on the Entity");
        attribute.setValidationRegex("^(/[^/ ]*)+/?$");
        return attribute;
    }

    private AttributeDefinition buildKeystorePasswordAttribute() {
        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("12ad2fd2-6ca1-4770-a28d-c2eb35ed02da");
        attribute.setName(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD_LABEL);
        attribute.setType(BaseAttributeDefinitionTypes.SECRET);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setDescription("Password for the Keystore");
        return attribute;
    }

    private AttributeDefinition buildKeystoreTypeAttribute() {
        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("731d8858-7c9c-4f84-8d87-937d81d3447b");
        attribute.setName(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE_LABEL);
        attribute.setType(BaseAttributeDefinitionTypes.LIST);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setValue(EnumSet.allOf(KeystoreType.class));
        attribute.setDescription("Type of the Keystore");
        return attribute;
    }
}
