package com.czertainly.provider.entity.keystore.enums;

import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;

import java.util.Arrays;

public enum KeystoreType {
    JKS("JKS"),
    PKCS12("PKCS12");

    private final String method;

    KeystoreType(String method) {
        this.method = method;
    }
    public String getCode() {
        return this.method;
    }

    public static KeystoreType findByCode(String method) {
        return (KeystoreType) Arrays.stream(values()).filter((k) -> {
            return k.method.equals(method);
        }).findFirst().orElseThrow(() -> {
            return new ValidationException(ValidationError.create("Unknown method {}", new Object[]{method}));
        });
    }
}
