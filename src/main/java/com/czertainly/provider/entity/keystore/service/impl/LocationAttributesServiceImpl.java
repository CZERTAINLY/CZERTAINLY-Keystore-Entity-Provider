package com.czertainly.provider.entity.keystore.service.impl;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.attribute.AttributeDefinition;
import com.czertainly.api.model.common.attribute.AttributeType;
import com.czertainly.api.model.common.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.content.BaseAttributeContent;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.provider.entity.keystore.AttributeConstants;
import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;
import com.czertainly.provider.entity.keystore.enums.KeystoreType;
import com.czertainly.provider.entity.keystore.service.LocationAttributeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class LocationAttributesServiceImpl implements LocationAttributeService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public List<AttributeDefinition> listLocationAttributes(EntityInstance entity) {
        logger.info("Getting the Attributes for Location of Entity {} with UUID {}", entity.getName(), entity.getUuid());

        List<AttributeDefinition> attrs = new ArrayList<>();
        attrs.add(buildKeystorePathAttribute());
        attrs.add(buildKeystorePasswordAttribute());
        attrs.add(buildKeystoreTypeAttribute());

        return attrs;
    }

    @Override
    public boolean validateLocationAttributes(EntityInstance entity, List<RequestAttributeDto> attributes) throws ValidationException {
        AttributeDefinitionUtils.validateAttributes(listLocationAttributes(entity), attributes);

        String keystoreType = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, attributes, BaseAttributeContent.class);

        if (!isKeystoreTypeSupported(keystoreType)) {
            logger.debug("Unsupported Keystore type {}", keystoreType);
            throw new ValidationException("Unsupported Keystore type " + keystoreType);
        }

        return true;
    }

    @Override
    public List<AttributeDefinition> listPushCertificateAttributes(EntityInstance entity) {
        logger.info("Getting the Attributes for Push of Entity {} with UUID {}", entity.getName(), entity.getUuid());

        List<AttributeDefinition> attrs = new ArrayList<>();
        attrs.add(buildAliasAttribute());

        return attrs;
    }

    @Override
    public boolean validatePushCertificateAttributes(EntityInstance entity, List<RequestAttributeDto> attributes) throws ValidationException {
        AttributeDefinitionUtils.validateAttributes(listPushCertificateAttributes(entity), attributes);
        return true;
    }

    @Override
    public List<AttributeDefinition> listGenerateCsrAttributes(EntityInstance entity) {
        logger.info("Getting the Attributes to generate CSR of Entity {} with UUID {}", entity.getName(), entity.getUuid());

        List<AttributeDefinition> attrs = new ArrayList<>();
        attrs.add(buildAliasAttribute());
        attrs.add(buildKeyAlgorithmAttribute());
        attrs.add(buildKeySizeAttribute());
        attrs.add(buildDnAttribute());
        attrs.add(buildSignatureAlgorithmAttribute());

        return attrs;
    }

    @Override
    public boolean validateGenerateCsrAttributes(EntityInstance entity, List<RequestAttributeDto> attributes) throws ValidationException {
        AttributeDefinitionUtils.validateAttributes(listGenerateCsrAttributes(entity), attributes);
        return true;
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
        attribute.setType(AttributeType.STRING);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setList(false);
        attribute.setMultiSelect(false);
        attribute.setDescription("Full path to the Keystore located on the Entity");
        attribute.setValidationRegex("^(/[^/ ]*)+/?$");
        return attribute;
    }

    private AttributeDefinition buildKeystorePasswordAttribute() {
        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("12ad2fd2-6ca1-4770-a28d-c2eb35ed02da");
        attribute.setName(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD_LABEL);
        attribute.setType(AttributeType.SECRET);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setList(false);
        attribute.setMultiSelect(false);
        attribute.setDescription("Password for the Keystore");
        return attribute;
    }

    private AttributeDefinition buildKeystoreTypeAttribute() {
        List<BaseAttributeContent<String>> keystoreTypes = new ArrayList<>();
        for (KeystoreType keystoreType : KeystoreType.values()) {
            BaseAttributeContent<String> ks = new BaseAttributeContent<>(keystoreType.getCode());
            keystoreTypes.add(ks);
        }

        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("731d8858-7c9c-4f84-8d87-937d81d3447b");
        attribute.setName(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE_LABEL);
        attribute.setType(AttributeType.STRING);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setList(true);
        attribute.setMultiSelect(false);
        attribute.setContent(keystoreTypes);
        attribute.setDescription("Type of the Keystore");
        return attribute;
    }

    private AttributeDefinition buildAliasAttribute() {
        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("a89139d5-d0de-443a-ad54-9b98a592ab6c");
        attribute.setName(AttributeConstants.ATTRIBUTE_ALIAS_NAME);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_ALIAS_NAME_LABEL);
        attribute.setType(AttributeType.STRING);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setList(false);
        attribute.setMultiSelect(false);
        attribute.setContent(new BaseAttributeContent<>("czertainly"));
        attribute.setDescription("Alias name");
        return attribute;
    }

    private AttributeDefinition buildKeyAlgorithmAttribute() {
        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("d76ae29c-45a8-4b01-a387-0285303db52e");
        attribute.setName(AttributeConstants.ATTRIBUTE_KEY_ALG_NAME);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_KEY_ALG_NAME_LABEL);
        attribute.setType(AttributeType.STRING);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setList(false);
        attribute.setMultiSelect(false);
        attribute.setDescription("Sets the key algorithm");
        return attribute;
    }

    private AttributeDefinition buildKeySizeAttribute() {
        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("d98331cb-5af2-4a0a-b254-c694e9d3e130");
        attribute.setName(AttributeConstants.ATTRIBUTE_KEY_SIZE_NAME);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_KEY_SIZE_NAME_LABEL);
        attribute.setType(AttributeType.STRING);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setList(false);
        attribute.setMultiSelect(false);
        attribute.setDescription("Sets the key size for the given algorithm");
        return attribute;
    }

    private AttributeDefinition buildDnAttribute() {
        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("63b7bb4e-751d-4546-bf77-2eb8217e1207");
        attribute.setName(AttributeConstants.ATTRIBUTE_DN_NAME);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_DN_NAME_LABEL);
        attribute.setType(AttributeType.STRING);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setList(false);
        attribute.setMultiSelect(false);
        attribute.setDescription("DN for the certificate signing request");
        return attribute;
    }

    private AttributeDefinition buildSignatureAlgorithmAttribute() {
        AttributeDefinition attribute = new AttributeDefinition();
        attribute.setUuid("724c38bb-2d12-4986-a690-781d0382fe1f");
        attribute.setName(AttributeConstants.ATTRIBUTE_SIG_ALG_NAME);
        attribute.setLabel(AttributeConstants.ATTRIBUTE_SIG_ALG_NAME_LABEL);
        attribute.setType(AttributeType.STRING);
        attribute.setRequired(true);
        attribute.setReadOnly(false);
        attribute.setVisible(true);
        attribute.setList(false);
        attribute.setMultiSelect(false);
        attribute.setDescription("Signature algorithm to sign the certificate signing request");
        return attribute;
    }
}
