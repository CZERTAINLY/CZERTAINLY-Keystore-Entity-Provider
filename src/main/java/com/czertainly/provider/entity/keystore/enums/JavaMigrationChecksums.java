package com.czertainly.provider.entity.keystore.enums;

/**
 * Stores the checksum of a Java-based migration.
 */
public enum JavaMigrationChecksums {
    V202211031300__AttributeV2Changes(349471228);
    private final int checksum;

    JavaMigrationChecksums(int checksum) {
        this.checksum = checksum;
    }

    public int getChecksum() {
        return checksum;
    }
}