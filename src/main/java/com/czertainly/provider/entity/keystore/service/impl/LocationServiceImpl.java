package com.czertainly.provider.entity.keystore.service.impl;

import com.czertainly.api.exception.LocationException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.attribute.AttributeDefinition;
import com.czertainly.api.model.common.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.content.BaseAttributeContent;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

        String keystorePath = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes(), BaseAttributeContent.class);
        String keystorePassword = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes(), BaseAttributeContent.class);
        String keystoreType = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes(), BaseAttributeContent.class);

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

            Map<String, Object> certificateMeta = new LinkedHashMap<>();
            certificateMeta.put(META_ALIAS, cert.getAlias());
            certificateMeta.put(META_ENTRY_TYPE, cert.isKeyEntry());

            certificateLocationDto.setMetadata(certificateMeta);

            List<AttributeDefinition> pushAttributes = new ArrayList<>();
            AttributeDefinition aliasAttribute = new AttributeDefinition();
            aliasAttribute.setName(AttributeConstants.ATTRIBUTE_ALIAS_NAME);
            aliasAttribute.setContent(new BaseAttributeContent<>(cert.getAlias()));
            pushAttributes.add(aliasAttribute);

            certificateLocationDto.setPushAttributes(pushAttributes);

            List<AttributeDefinition> csrAttributes = new ArrayList<>();
            if (cert.isKeyEntry()) {
                AttributeDefinition subjectDnAttribute = new AttributeDefinition();
                subjectDnAttribute.setName(AttributeConstants.ATTRIBUTE_DN_NAME);
                subjectDnAttribute.setContent(new BaseAttributeContent<>(cert.getCertificate().getSubjectDN().toString()));
                csrAttributes.add(subjectDnAttribute);

                PublicKey pubk = cert.getCertificate().getPublicKey();
                AttributeDefinition keyAlgorithmAttribute = new AttributeDefinition();
                keyAlgorithmAttribute.setName(AttributeConstants.ATTRIBUTE_KEY_ALG_NAME);
                keyAlgorithmAttribute.setContent(new BaseAttributeContent<>(pubk.getAlgorithm()));
                csrAttributes.add(keyAlgorithmAttribute);

                AttributeDefinition keyLengthAttribute = new AttributeDefinition();
                keyLengthAttribute.setName(AttributeConstants.ATTRIBUTE_KEY_SIZE_NAME);
                if (pubk instanceof RSAPublicKey) {
                    RSAPublicKey rsaPubk = (RSAPublicKey) pubk;
                    keyLengthAttribute.setContent(new BaseAttributeContent<>(String.valueOf(rsaPubk.getModulus().bitLength())));
                } else if (pubk instanceof ECPublicKey) {
                    ECPublicKey ecPubk = (ECPublicKey) pubk;
                    keyLengthAttribute.setContent(new BaseAttributeContent<>(String.valueOf(ecPubk.getParams().getCurve().getField().getFieldSize())));
                } else if (pubk instanceof DSAPublicKey) {
                    DSAPublicKey dsaPubk = (DSAPublicKey) pubk;
                    keyLengthAttribute.setContent(new BaseAttributeContent<>(String.valueOf(dsaPubk.getParams().getP().bitLength())));
                } else {
                    keyLengthAttribute.setContent(new BaseAttributeContent<>("unknown"));
                }
                csrAttributes.add(keyLengthAttribute);

                AttributeDefinition signatureAlgorithmAttribute = new AttributeDefinition();
                signatureAlgorithmAttribute.setName(AttributeConstants.ATTRIBUTE_SIG_ALG_NAME);
                signatureAlgorithmAttribute.setContent(new BaseAttributeContent<>(cert.getCertificate().getSigAlgName()));
                csrAttributes.add(signatureAlgorithmAttribute);

                // alias include
                csrAttributes.add(aliasAttribute);
            }

            certificateLocationDto.setCsrAttributes(csrAttributes);

            certificates.add(certificateLocationDto);
        }

        Map<String, Object> locationMeta = new LinkedHashMap<>();
        locationMeta.put(META_KSP, KeystoreResponseUtil.getKeystoreProvider(response));

        LocationDetailResponseDto responseDto = new LocationDetailResponseDto();
        responseDto.setMultipleEntries(true);
        responseDto.setSupportKeyManagement(true);
        responseDto.setCertificates(certificates);
        responseDto.setMetadata(locationMeta);

        return responseDto;
    }

    @TrackExecutionTime
    @Override
    public PushCertificateResponseDto pushCertificateToLocation(String entityUuid, PushCertificateRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());
        locationAttributeService.validatePushCertificateAttributes(entity, request.getPushAttributes());

        String alias = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_ALIAS_NAME, request.getPushAttributes(), BaseAttributeContent.class);
        String keystorePath = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes(), BaseAttributeContent.class);
        String keystorePassword = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes(), BaseAttributeContent.class);
        String keystoreType = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes(), BaseAttributeContent.class);

        PushCertificateResponseDto responseDto = new PushCertificateResponseDto();

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put(META_ALIAS, alias);

        responseDto.setCertificateMetadata(meta);

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

        String alias = (String) request.getCertificateMetadata().get(META_ALIAS);

        if (!StringUtils.isNotBlank(alias)) {
            String message = "Alias not found in the certificate metadata for Entity " + entityUuid + ". Nothing to remove";
            logger.info(message);

            responseDto.setCertificateMetadata(request.getCertificateMetadata());
            return responseDto;
        }

        String keystorePath = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes(), BaseAttributeContent.class);
        String keystorePassword = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes(), BaseAttributeContent.class);
        String keystoreType = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes(), BaseAttributeContent.class);

        String response = sshService.runRemoteCommand(
                KeytoolCommand.prepareKeytoolRemoveCertificateCommand(keystorePath, keystoreType, keystorePassword, alias),
                entity);

        if (response.startsWith(KEYTOOL_ERROR_PREFIX)) {
            logger.info("Failed to remove alias {} from Keystore {} for Entity {}", alias, keystorePath, entityUuid);
            throw new LocationException(response);
        }

        Map<String, Object> meta = request.getCertificateMetadata();
        meta.remove(META_ALIAS);
        responseDto.setCertificateMetadata(meta);

        return responseDto;
    }

    @TrackExecutionTime
    @Override
    public GenerateCsrResponseDto generateCsrLocation(String entityUuid, GenerateCsrRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());
        locationAttributeService.validateGenerateCsrAttributes(entity, request.getCsrAttributes());

        String alias = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_ALIAS_NAME, request.getCsrAttributes(), BaseAttributeContent.class);
        String keyalg = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEY_ALG_NAME, request.getCsrAttributes(), BaseAttributeContent.class);
        String keysize = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEY_SIZE_NAME, request.getCsrAttributes(), BaseAttributeContent.class);
        String sigalg = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_SIG_ALG_NAME, request.getCsrAttributes(), BaseAttributeContent.class);
        String dname = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_DN_NAME, request.getCsrAttributes(), BaseAttributeContent.class);
        String keystorePath = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes(), BaseAttributeContent.class);
        String keystorePassword = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes(), BaseAttributeContent.class);
        String keystoreType = AttributeDefinitionUtils.getAttributeContentValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes(), BaseAttributeContent.class);

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
            aliasRequestAttribute.setContent(new BaseAttributeContent<>(alias));
            pushAttributes.add(aliasRequestAttribute);

            responseDto.setPushAttributes(pushAttributes);

            Map<String, Object> certificateMeta = new LinkedHashMap<>();
            certificateMeta.put(META_ALIAS, alias);
            certificateMeta.put(META_ENTRY_TYPE, true);

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
}
