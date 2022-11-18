package com.czertainly.provider.entity.keystore.service.impl;

import com.czertainly.api.exception.LocationException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.AttributeType;
import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.InfoAttribute;
import com.czertainly.api.model.common.attribute.v2.InfoAttributeProperties;
import com.czertainly.api.model.common.attribute.v2.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.BooleanAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.SecretAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.connector.entity.*;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.provider.entity.keystore.AttributeConstants;
import com.czertainly.provider.entity.keystore.aop.TrackExecutionTime;
import com.czertainly.provider.entity.keystore.command.KeystoreCertificate;
import com.czertainly.provider.entity.keystore.command.KeytoolCommand;
import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;
import com.czertainly.provider.entity.keystore.service.EntityService;
import com.czertainly.provider.entity.keystore.service.LocationAttributeService;
import com.czertainly.provider.entity.keystore.service.LocationService;
import com.czertainly.provider.entity.keystore.service.SshService;
import com.czertainly.provider.entity.keystore.util.CertificateUtil;
import com.czertainly.provider.entity.keystore.util.KeystoreResponseUtil;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class LocationServiceImpl implements LocationService {

    public static final String META_ALIAS = "keystore.alias";
    public static final String META_ENTRY_TYPE = "keystore.containsKey";
    public static final String META_KSP = "keystore.provider";
    private static final String KEYTOOL_ERROR_PREFIX = "keytool error:";
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private EntityService entityService;
    private SshService sshService;
    private LocationAttributeService locationAttributeService;

    @Autowired
    public void setEntityService(EntityService entityService) {
        this.entityService = entityService;
    }

    @Autowired
    public void setSshService(SshService sshService) {
        this.sshService = sshService;
    }

    @Autowired
    public void setLocationAttributeService(LocationAttributeService locationAttributeService) {
        this.locationAttributeService = locationAttributeService;
    }

    @TrackExecutionTime
    @Override
    public LocationDetailResponseDto getLocationDetail(String entityUuid, LocationDetailRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);

        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());

        String keystorePath = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes(), StringAttributeContent.class).getData();
        String keystorePassword = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes(), SecretAttributeContent.class).getData().getSecret();
        String keystoreType = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes(), StringAttributeContent.class).getData();

        String response = sshService.runRemoteCommand(KeytoolCommand.prepareKeytoolListCommand(keystorePath, keystoreType, keystorePassword), entity);

        if (response.startsWith(KEYTOOL_ERROR_PREFIX)) {
            logger.info("Keystore {} cannot be processed for Entity {}", keystorePath, entityUuid);
            throw new LocationException(response);
        }

        List<CertificateLocationDto> certificates = new ArrayList<>();
        // parse the response and get certificates
        List<KeystoreCertificate> certs = KeystoreResponseUtil.getAllKeystoreCertificates(response);
        for (KeystoreCertificate cert : certs) {
            CertificateLocationDto certificateLocationDto = new CertificateLocationDto();
            certificateLocationDto.setCertificateData(CertificateUtil.getBase64Certificate(cert.getCertificate()));

            certificateLocationDto.setWithKey(cert.isKeyEntry());

            List<InfoAttribute> certificateMeta = List.of(getAliasMetadata(cert.getAlias()), getEntryTypeMetadata(cert.isKeyEntry()));

            certificateLocationDto.setMetadata(certificateMeta);

            List<DataAttribute> pushAttributes = new ArrayList<>();
            DataAttribute aliasAttribute = new DataAttribute();
            aliasAttribute.setName(AttributeConstants.ATTRIBUTE_ALIAS_NAME);
            aliasAttribute.setContent(List.of(new StringAttributeContent(cert.getAlias())));
            pushAttributes.add(aliasAttribute);

            certificateLocationDto.setPushAttributes(pushAttributes);

            List<DataAttribute> csrAttributes = new ArrayList<>();
            if (cert.isKeyEntry()) {
                DataAttribute subjectDnAttribute = new DataAttribute();
                subjectDnAttribute.setName(AttributeConstants.ATTRIBUTE_DN_NAME);
                subjectDnAttribute.setContent(List.of(new StringAttributeContent(cert.getCertificate().getSubjectDN().toString())));
                csrAttributes.add(subjectDnAttribute);

                PublicKey pubk = cert.getCertificate().getPublicKey();
                DataAttribute keyAlgorithmAttribute = new DataAttribute();
                keyAlgorithmAttribute.setName(AttributeConstants.ATTRIBUTE_KEY_ALG_NAME);
                keyAlgorithmAttribute.setContent(List.of(new StringAttributeContent(pubk.getAlgorithm())));
                csrAttributes.add(keyAlgorithmAttribute);

                DataAttribute keyLengthAttribute = new DataAttribute();
                keyLengthAttribute.setName(AttributeConstants.ATTRIBUTE_KEY_SIZE_NAME);
                if (pubk instanceof RSAPublicKey) {
                    RSAPublicKey rsaPubk = (RSAPublicKey) pubk;
                    keyLengthAttribute.setContent(List.of(new StringAttributeContent(String.valueOf(rsaPubk.getModulus().bitLength()))));
                } else if (pubk instanceof ECPublicKey) {
                    ECPublicKey ecPubk = (ECPublicKey) pubk;
                    keyLengthAttribute.setContent(List.of(new StringAttributeContent(String.valueOf(ecPubk.getParams().getCurve().getField().getFieldSize()))));
                } else if (pubk instanceof DSAPublicKey) {
                    DSAPublicKey dsaPubk = (DSAPublicKey) pubk;
                    keyLengthAttribute.setContent(List.of(new StringAttributeContent(String.valueOf(dsaPubk.getParams().getP().bitLength()))));
                } else {
                    keyLengthAttribute.setContent(List.of(new StringAttributeContent("unknown")));
                }
                csrAttributes.add(keyLengthAttribute);

                DataAttribute signatureAlgorithmAttribute = new DataAttribute();
                signatureAlgorithmAttribute.setName(AttributeConstants.ATTRIBUTE_SIG_ALG_NAME);
                signatureAlgorithmAttribute.setContent(List.of(new StringAttributeContent(cert.getCertificate().getSigAlgName())));
                csrAttributes.add(signatureAlgorithmAttribute);

                // alias include
                csrAttributes.add(aliasAttribute);
            }

            certificateLocationDto.setCsrAttributes(csrAttributes);

            certificates.add(certificateLocationDto);
        }

        LocationDetailResponseDto responseDto = new LocationDetailResponseDto();
        responseDto.setMultipleEntries(true);
        responseDto.setSupportKeyManagement(true);
        responseDto.setCertificates(certificates);
        responseDto.setMetadata(List.of(getKspMetadata(KeystoreResponseUtil.getKeystoreProvider(response))));

        return responseDto;
    }

    @TrackExecutionTime
    @Override
    public PushCertificateResponseDto pushCertificateToLocation(String entityUuid, PushCertificateRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());
        locationAttributeService.validatePushCertificateAttributes(entity, request.getPushAttributes());

        String alias = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_ALIAS_NAME, request.getPushAttributes(), StringAttributeContent.class).getData();
        String keystorePath = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes(), StringAttributeContent.class).getData();
        String keystorePassword = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes(), SecretAttributeContent.class).getData().getSecret();
        String keystoreType = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes(), StringAttributeContent.class).getData();

        PushCertificateResponseDto responseDto = new PushCertificateResponseDto();

        responseDto.setCertificateMetadata(List.of(getAliasMetadata(alias)));

        String filename = "/tmp/" + generateRandomFilename();

        // let's check we have the certificate as input
        X509Certificate certificate;
        try {
            certificate = CertificateUtil.parseCertificate(request.getCertificate());
        } catch (CertificateException e) {
            logger.debug("Failed to parse certificate {}", request.getCertificate());
            throw new LocationException(e.getMessage());
        }

        try {
            FileUtils.writeByteArrayToFile(new File(filename), certificate.getEncoded());
        } catch (IOException | CertificateEncodingException e) {
            logger.debug("Error when creating the temporary certificate file for push to location {}", keystorePath, e);
            throw new LocationException(e.getMessage());
        }

        try {
            sshService.uploadFile(entity, filename, filename);

            String response = sshService.runRemoteCommand(
                    KeytoolCommand.prepareKeytoolPushCertificateCommand(keystorePath, keystoreType, keystorePassword, filename, alias),
                    entity);

            if (response.startsWith(KEYTOOL_ERROR_PREFIX)) {
                logger.info("Keystore {} cannot be processed for Entity {}", keystorePath, entityUuid);

                throw new LocationException(response);
            }

            String updResponse = sshService.runRemoteCommand(KeytoolCommand.prepareKeytoolDetailCommand(keystorePath, keystoreType, keystorePassword, alias), entity);
            List<KeystoreCertificate> certs = KeystoreResponseUtil.getAllKeystoreCertificates(updResponse);
            if (certs.isEmpty()) {
                throw new LocationException(response);
            } else {
                responseDto.setCertificateMetadata(List.of(getEntryTypeMetadata(certs.get(0).isKeyEntry())));
                responseDto.setWithKey(certs.get(0).isKeyEntry());
            }

            return responseDto;

        } finally {

            sshService.runRemoteCommand("rm " + filename, entity);

            try {
                FileUtils.delete(new File(filename));
            } catch (IOException e) {
                logger.debug("Failed to delete temporary certificate file after push to location {}", keystorePath, e);
                //throw new LocationException(e.getMessage());
            }
        }
    }

    @TrackExecutionTime
    @Override
    public RemoveCertificateResponseDto removeCertificateFromLocation(String entityUuid, RemoveCertificateRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());

        LocationDetailRequestDto detailRequest = new LocationDetailRequestDto();
        detailRequest.setLocationAttributes(request.getLocationAttributes());
        List<CertificateLocationDto> certificatesInLocation = getLocationDetail(entityUuid, detailRequest).getCertificates();
        if (certificatesInLocation != null && certificatesInLocation.size() == 1) {
            throw new LocationException("Java keystore cannot be empty.");
        }

        RemoveCertificateResponseDto responseDto = new RemoveCertificateResponseDto();

        String alias = AttributeDefinitionUtils.getSingleItemAttributeContentValue(META_ALIAS, request.getCertificateMetadata(), StringAttributeContent.class).getData();

        if (!StringUtils.isNotBlank(alias)) {
            String message = "Alias not found in the certificate metadata for Entity " + entityUuid + ". Nothing to remove";
            logger.info(message);

            responseDto.setCertificateMetadata(request.getCertificateMetadata());
            return responseDto;
        }

        String keystorePath = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes(), StringAttributeContent.class).getData();
        String keystorePassword = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes(), SecretAttributeContent.class).getData().getSecret();
        String keystoreType = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes(), StringAttributeContent.class).getData();

        String response = sshService.runRemoteCommand(
                KeytoolCommand.prepareKeytoolRemoveCertificateCommand(keystorePath, keystoreType, keystorePassword, alias),
                entity);

        if (response.startsWith(KEYTOOL_ERROR_PREFIX)) {
            logger.info("Failed to remove alias {} from Keystore {} for Entity {}", alias, keystorePath, entityUuid);
            throw new LocationException(response);
        }

        responseDto.setCertificateMetadata(request.getCertificateMetadata().stream().filter(e -> !entity.getName().equals(META_ALIAS)).collect(Collectors.toList()));

        return responseDto;
    }

    @TrackExecutionTime
    @Override
    public GenerateCsrResponseDto generateCsrLocation(String entityUuid, GenerateCsrRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());
        locationAttributeService.validateGenerateCsrAttributes(entity, request.getCsrAttributes());

        String alias = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_ALIAS_NAME, request.getCsrAttributes(), StringAttributeContent.class).getData();
        String keyalg = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEY_ALG_NAME, request.getCsrAttributes(), StringAttributeContent.class).getData();
        String keysize = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEY_SIZE_NAME, request.getCsrAttributes(), StringAttributeContent.class).getData();
        String sigalg = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_SIG_ALG_NAME, request.getCsrAttributes(), StringAttributeContent.class).getData();
        String dname = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_DN_NAME, request.getCsrAttributes(), StringAttributeContent.class).getData();
        String keystorePath = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes(), StringAttributeContent.class).getData();
        String keystorePassword = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes(), SecretAttributeContent.class).getData().getSecret();
        String keystoreType = AttributeDefinitionUtils.getSingleItemAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes(), StringAttributeContent.class).getData();

        // TODO: validation of the attribute values

        String response;
        if (!request.isRenewal()) {

            response = sshService.runRemoteCommand(
                    KeytoolCommand.prepareKeytoolGenerateKeyPairCommand(keystorePath, keystoreType, keystorePassword,
                            alias, keyalg, keysize, sigalg, dname),
                    entity);

            if (response.startsWith(KEYTOOL_ERROR_PREFIX)) {
                logger.info("Failed to generate new key pair for alias {} from Keystore {} for Entity {}", alias, keystorePath, entityUuid);
                throw new LocationException(response);
            }
        }

        String filename = "/tmp/" + generateRandomFilename();

        response = sshService.runRemoteCommand(
                KeytoolCommand.prepareKeytoolGenerateCsrCommand(keystorePath, keystoreType, keystorePassword,
                        alias, sigalg, filename),
                entity);

        if (response.startsWith(KEYTOOL_ERROR_PREFIX)) {
            logger.info("Failed to generate CSR for alias {} from Keystore {} for Entity {}", alias, keystorePath, entityUuid);
            throw new LocationException(response);
        }

        try {
            sshService.downloadFile(entity, filename, filename);
            byte[] csr = FileUtils.readFileToByteArray(new File(filename));

            GenerateCsrResponseDto responseDto = new GenerateCsrResponseDto();
            responseDto.setCsr(Base64.getEncoder().encodeToString(csr));

            List<RequestAttributeDto> pushAttributes = new ArrayList<>();

            RequestAttributeDto aliasRequestAttribute = new RequestAttributeDto();
            aliasRequestAttribute.setName(AttributeConstants.ATTRIBUTE_ALIAS_NAME);
            aliasRequestAttribute.setContent(List.of(new StringAttributeContent(alias)));
            pushAttributes.add(aliasRequestAttribute);

            responseDto.setPushAttributes(pushAttributes);

            List<InfoAttribute> certificateMeta = List.of(getAliasMetadata(alias), getEntryTypeMetadata(true));
            responseDto.setMetadata(certificateMeta);

            return responseDto;

        } catch (IOException e) {
            logger.debug("Failed to read CSR file {} for location {}", filename, keystorePath, e);
            throw new LocationException(e.getMessage());
        } finally {

            sshService.runRemoteCommand("rm " + filename, entity);

            try {
                FileUtils.delete(new File(filename));
            } catch (IOException e) {
                logger.debug("Failed to delete temporary CSR file {} for location {}", filename, keystorePath, e);
                //throw new LocationException(e.getMessage());
            }
        }
    }

    private String generateRandomFilename() {
        SecureRandom random = new SecureRandom();
        byte[] r = new byte[8];
        random.nextBytes(r);
        return Base64.getUrlEncoder().encodeToString(r);
    }

    private InfoAttribute getAliasMetadata(String alias) {
        //Alias
        InfoAttribute attribute = new InfoAttribute();
        attribute.setName(META_ALIAS);
        attribute.setUuid("d7c95fb8-61a0-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Alias Name for the JKS Entry");

        InfoAttributeProperties attributeProperties = new InfoAttributeProperties();
        attributeProperties.setLabel("Alias");
        attributeProperties.setVisible(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new StringAttributeContent(alias)));

        return attribute;
    }

    private InfoAttribute getEntryTypeMetadata(Boolean entryType) {
        //Alias
        InfoAttribute attribute = new InfoAttribute();
        attribute.setName(META_ENTRY_TYPE);
        attribute.setUuid("d7c962c4-61a0-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.BOOLEAN);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Does the location contains the key for the certificate");

        InfoAttributeProperties attributeProperties = new InfoAttributeProperties();
        attributeProperties.setLabel("Is Private Key Available");
        attributeProperties.setVisible(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new BooleanAttributeContent(entryType)));

        return attribute;
    }

    private InfoAttribute getKspMetadata(String ksp) {
        //Alias
        InfoAttribute attribute = new InfoAttribute();
        attribute.setName(META_KSP);
        attribute.setUuid("d7c96472-61a0-11ed-9b6a-0242ac120002");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setType(AttributeType.META);
        attribute.setDescription("Key Store Provider");

        InfoAttributeProperties attributeProperties = new InfoAttributeProperties();
        attributeProperties.setLabel("Key Store Provider");
        attributeProperties.setVisible(true);

        attribute.setProperties(attributeProperties);
        attribute.setContent(List.of(new StringAttributeContent(ksp)));

        return attribute;
    }
}
