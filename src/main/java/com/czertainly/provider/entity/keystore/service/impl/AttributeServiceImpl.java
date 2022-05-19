package com.czertainly.provider.entity.keystore.service.impl;

import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.common.*;
import com.czertainly.api.model.core.credential.CredentialDto;
import com.czertainly.provider.entity.keystore.AttributeConstants;
import com.czertainly.provider.entity.keystore.service.AttributeService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.provider.entity.keystore.enums.AuthenticationType;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.*;
import java.util.stream.Collectors;

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
            authType.setValue((ArrayList)EnumSet.allOf(AuthenticationType.class).stream().map(AuthenticationType::getCode).collect(Collectors.toList()));
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

//        CredentialDto credential = AttributeDefinitionUtils.getCredentialValue(AttributeConstants.ATTRIBUTE_CREDENTIAL, attributes);
//        if (!isCredentialSupported(credential)) {
//            logger.debug("Unsupported authentication type {}", credential.getKind());
//            throw new ValidationException("Unsupported authentication type " + credential.getKind());
//        }

        return true;
    }

    private boolean isKindSupported(String kind) {
        return kind.equals("Keystore");
    }

    private boolean isCredentialSupported(CredentialDto credential) {
        if (StringUtils.isNotBlank(credential.getKind())) {
            if (credential.getKind().equals("Basic")) {
                return true;
            }
        }

        for (AuthenticationType c : AuthenticationType.values()) {
            if (c.name().equals(credential.getKind())) {
                return true;
            }
        }
        return false;
    }


}
