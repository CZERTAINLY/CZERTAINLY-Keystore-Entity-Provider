package com.czertainly.provider.entity.keystore.util;

import com.czertainly.provider.entity.keystore.command.KeystoreCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class KeystoreResponseUtil {

    private static final Logger logger = LoggerFactory.getLogger(KeystoreResponseUtil.class);

    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

    private static final String ALIAS_NAME_PREFIX = "Alias name: ";
    private static final String ENTRY_TYPE_PREFIX = "Entry type: ";
    private static final String CHAIN_LENGTH_PREFIX = "Certificate chain length: ";
    private static final String KEYSTORE_PROVIDER_PREFIX = "Keystore provider: ";

    private static final String PRIVATE_KEY_ENTRY = "PrivateKeyEntry";

    public static List<KeystoreCertificate> getAllKeystoreCertificates(String response) {
        List<KeystoreCertificate> certs = new ArrayList<>();

        if (!response.contains(BEGIN_CERTIFICATE)) {
            return certs;
        }

        while (response.contains(BEGIN_CERTIFICATE)) {
            // remove everything before the alias name
            response = response.substring(response.indexOf(ALIAS_NAME_PREFIX));
            String aliasRow = response.substring(response.indexOf(ALIAS_NAME_PREFIX), response.indexOf("\n"));
            String aliasName = aliasRow.split(ALIAS_NAME_PREFIX)[1];

            // remove everything before the entry type
            response = response.substring(response.indexOf(ENTRY_TYPE_PREFIX));
            String entryTypeRow = response.substring(response.indexOf(ENTRY_TYPE_PREFIX), response.indexOf("\n"));
            String entryType = entryTypeRow.split(ENTRY_TYPE_PREFIX)[1];

            int chainLength = 1;

            // the PrivateKeyEntry can have a chain of certificates
            if (entryType.equals(PRIVATE_KEY_ENTRY)) {
                response = response.substring(response.indexOf(CHAIN_LENGTH_PREFIX));
                String chainLengthRow = response.substring(response.indexOf(CHAIN_LENGTH_PREFIX), response.indexOf("\n"));
                chainLength = Integer.parseInt(chainLengthRow.split(CHAIN_LENGTH_PREFIX)[1]);
            }

            for (int x = 0; x < chainLength; x++) {
                String rfcCert = response.substring(
                        response.indexOf(BEGIN_CERTIFICATE),
                        response.indexOf(END_CERTIFICATE) + END_CERTIFICATE.length()
                );

                try {
                    X509Certificate certificate = CertificateUtil.parseCertificate(rfcCert);
                    if (x > 0) {
                        certs.add(new KeystoreCertificate(certificate, false, aliasName));
                    } else {
                        certs.add(new KeystoreCertificate(certificate, entryType.equals(PRIVATE_KEY_ENTRY), aliasName));
                    }
                } catch (CertificateException e) {
                    logger.error("Cannot parse the certificate for alias {}", aliasName, e);
                }

                response = response.substring(response.indexOf(END_CERTIFICATE) + END_CERTIFICATE.length());
            }
        }

        return certs;
    }

    public static String getKeystoreProvider(String response) {
        if (!response.contains(KEYSTORE_PROVIDER_PREFIX)) {
            return null;
        }

        response = response.substring(response.indexOf(KEYSTORE_PROVIDER_PREFIX));
        String kspRow = response.substring(response.indexOf(KEYSTORE_PROVIDER_PREFIX), response.indexOf("\n"));
        String ksp = kspRow.split(KEYSTORE_PROVIDER_PREFIX)[1];

        return ksp;
    }
}
