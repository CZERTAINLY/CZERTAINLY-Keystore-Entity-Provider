package com.czertainly.provider.entity.keystore.command;

import java.security.cert.X509Certificate;

public class KeystoreCertificate {

    private X509Certificate certificate;
    private boolean isKeyEntry;
    private String alias;

    public KeystoreCertificate(X509Certificate certificate, boolean isKeyEntry, String alias) {
        this.certificate = certificate;
        this.isKeyEntry = isKeyEntry;
        this.alias = alias;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public boolean isKeyEntry() {
        return isKeyEntry;
    }

    public String getAlias() {
        return alias;
    }
}
