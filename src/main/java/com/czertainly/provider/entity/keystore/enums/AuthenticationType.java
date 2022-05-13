package com.czertainly.provider.entity.keystore.enums;

import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;

import java.util.Arrays;

public enum AuthenticationType {
    BASIC("Username / Password"),
    SSH("Username / SSH Private Key");

    private String method;

    private AuthenticationType(String method) {
        this.method = method;
    }
    public String getCode() {
        return this.method;
    }

    public static AuthenticationType findByCode(String method) {
        return (AuthenticationType) Arrays.stream(values()).filter((k) -> {
            return k.method.equals(method);
        }).findFirst().orElseThrow(() -> {
            return new ValidationException(ValidationError.create("Unknown method {}", new Object[]{method}));
        });
    }
}
