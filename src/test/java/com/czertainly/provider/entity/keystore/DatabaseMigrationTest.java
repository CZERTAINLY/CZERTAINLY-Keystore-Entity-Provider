package com.czertainly.provider.entity.keystore;

import com.czertainly.core.util.DatabaseMigrationUtils;
import com.czertainly.provider.entity.keystore.enums.JavaMigrationChecksums;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Simple tests for calculating checksums and validating the migration scripts integrity.
 */
public class DatabaseMigrationTest {

    @Test
    public void testCalculateChecksum_V202207021230__AttributeChanges() {
        int checksum = DatabaseMigrationUtils.calculateChecksum("src/main/java/db/migration/V202211031300__AttributeV2Changes.java");

        Assertions.assertEquals(JavaMigrationChecksums.V202211031300__AttributeV2Changes.getChecksum(), checksum);
    }

}
