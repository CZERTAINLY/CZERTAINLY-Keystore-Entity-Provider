package com.czertainly.provider.entity.keystore.service.impl;

import com.czertainly.api.exception.LocationException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.RequestAttributeDto;
import com.czertainly.api.model.connector.entity.*;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.provider.entity.keystore.AttributeConstants;
import com.czertainly.provider.entity.keystore.command.KeystoreCertificate;
import com.czertainly.provider.entity.keystore.command.KeytoolCommand;
import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;
import com.czertainly.provider.entity.keystore.service.*;
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
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Service
public class LocationServiceImpl implements LocationService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final String KEYTOOL_ERROR_PREFIX = "keytool error:";

    public static final String META_ALIAS = "keystore.alias";
    public static final String META_ENTRY_TYPE = "keystore.containsKey";

    public static final String META_KSP = "keystore.provider";

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

    private EntityService entityService;
    private SshService sshService;
    private LocationAttributeService locationAttributeService;

    @Override
    public LocationDetailResponseDto getLocationDetail(String entityUuid, LocationDetailRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);

        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());

        String keystorePath = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes());
        String keystorePassword = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes());
        String keystoreType = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes());

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

            if (cert.isKeyEntry()) {
                certificateLocationDto.setWithKey(true);
            } else {
                certificateLocationDto.setWithKey(false);
            }

            Map<String, Object> certificateMeta = new LinkedHashMap<>();
            certificateMeta.put(META_ALIAS, cert.getAlias());
            certificateMeta.put(META_ENTRY_TYPE, cert.isKeyEntry());

            certificateLocationDto.setMetadata(certificateMeta);

            List<RequestAttributeDto> pushAttributes = new ArrayList<>();
            RequestAttributeDto aliasAttribute = new RequestAttributeDto();
            aliasAttribute.setName(AttributeConstants.ATTRIBUTE_ALIAS_NAME);
            aliasAttribute.setValue(cert.getAlias());
            pushAttributes.add(aliasAttribute);

            certificateLocationDto.setPushAttributes(pushAttributes);

            List<RequestAttributeDto> csrAttributes = new ArrayList<>();
            if (cert.isKeyEntry()) {
                RequestAttributeDto subjectDnAttribute = new RequestAttributeDto();
                subjectDnAttribute.setName(AttributeConstants.ATTRIBUTE_DN_NAME);
                subjectDnAttribute.setValue(cert.getCertificate().getSubjectDN().toString());
                csrAttributes.add(subjectDnAttribute);

                PublicKey pubk = cert.getCertificate().getPublicKey();
                RequestAttributeDto keyAlgorithmAttribute = new RequestAttributeDto();
                keyAlgorithmAttribute.setName(AttributeConstants.ATTRIBUTE_KEY_ALG_NAME);
                keyAlgorithmAttribute.setValue(pubk.getAlgorithm());
                csrAttributes.add(keyAlgorithmAttribute);

                RequestAttributeDto keyLengthAttribute = new RequestAttributeDto();
                keyLengthAttribute.setName(AttributeConstants.ATTRIBUTE_KEY_SIZE_NAME);
                if (pubk instanceof RSAPublicKey) {
                    RSAPublicKey rsaPubk = (RSAPublicKey) pubk;
                    keyLengthAttribute.setValue(String.valueOf(rsaPubk.getModulus().bitLength()));
                } else if (pubk instanceof ECPublicKey) {
                    ECPublicKey ecPubk = (ECPublicKey) pubk;
                    keyLengthAttribute.setValue(String.valueOf(ecPubk.getParams().getCurve().getField().getFieldSize()));
                } else if (pubk instanceof DSAPublicKey) {
                    DSAPublicKey dsaPubk = (DSAPublicKey) pubk;
                    keyLengthAttribute.setValue(String.valueOf(dsaPubk.getParams().getP().bitLength()));
                } else {
                    keyLengthAttribute.setValue("unknown");
                }
                csrAttributes.add(keyLengthAttribute);

                RequestAttributeDto signatureAlgorithmAttribute = new RequestAttributeDto();
                signatureAlgorithmAttribute.setName(AttributeConstants.ATTRIBUTE_SIG_ALG_NAME);
                signatureAlgorithmAttribute.setValue(cert.getCertificate().getSigAlgName());
                csrAttributes.add(signatureAlgorithmAttribute);
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

    @Override
    public PushCertificateResponseDto pushCertificateToLocation(String entityUuid, PushCertificateRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());
        locationAttributeService.validatePushCertificateAttributes(entity, request.getPushAttributes());

        String alias = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_ALIAS_NAME, request.getPushAttributes());
        String keystorePath = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes());
        String keystorePassword = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes());
        String keystoreType = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes());

        String filename = "/tmp/" + generateRandomFilename();

        try {
            FileUtils.writeByteArrayToFile(new File(filename), Base64.getDecoder().decode(request.getCertificate()));
        } catch (IOException e) {
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

            PushCertificateResponseDto responseDto = new PushCertificateResponseDto();

            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put(META_ALIAS, alias);

            responseDto.setCertificateMetadata(meta);

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

    @Override
    public RemoveCertificateResponseDto removeCertificateFromLocation(String entityUuid, RemoveCertificateRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());

        RemoveCertificateResponseDto responseDto = new RemoveCertificateResponseDto();

        String alias = (String) request.getCertificateMetadata().get(META_ALIAS);
        if (!StringUtils.isNotBlank(alias)) {
            String message = "Alias not found in the certificate metadata for Entity " + entityUuid + ". Nothing to remove";
            logger.info(message);

            responseDto.setCertificateMetadata(request.getCertificateMetadata());
            return responseDto;
        }

        String keystorePath = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes());
        String keystorePassword = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes());
        String keystoreType = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes());

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

    @Override
    public GenerateCsrResponseDto generateCsrLocation(String entityUuid, GenerateCsrRequestDto request) throws NotFoundException, LocationException {
        EntityInstance entity = entityService.getEntityInstance(entityUuid);
        locationAttributeService.validateLocationAttributes(entity, request.getLocationAttributes());
        locationAttributeService.validateGenerateCsrAttributes(entity, request.getCsrAttributes());

        String alias = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_ALIAS_NAME, request.getCsrAttributes());
        String keyalg = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEY_ALG_NAME, request.getCsrAttributes());
        String keysize = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEY_SIZE_NAME, request.getCsrAttributes());
        String sigalg = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_SIG_ALG_NAME, request.getCsrAttributes());
        String dname = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_DN_NAME, request.getCsrAttributes());
        String keystorePath = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PATH, request.getLocationAttributes());
        String keystorePassword = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_PASSWORD, request.getLocationAttributes());
        String keystoreType = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_KEYSTORE_TYPE, request.getLocationAttributes());

        // TODO: validation of the attribute values

        String response = sshService.runRemoteCommand(
                KeytoolCommand.prepareKeytoolGenerateKeyPairCommand(keystorePath, keystoreType, keystorePassword,
                        alias, keyalg, keysize, sigalg, dname),
                entity);

        if (response.startsWith(KEYTOOL_ERROR_PREFIX)) {
            logger.info("Failed to generate new key pair for alias {} from Keystore {} for Entity {}", alias, keystorePath, entityUuid);
            throw new LocationException(response);
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
            aliasRequestAttribute.setValue(alias);
            pushAttributes.add(aliasRequestAttribute);

            responseDto.setPushAttributes(pushAttributes);

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
        return Base64.getEncoder().encodeToString(r);
    }
}
