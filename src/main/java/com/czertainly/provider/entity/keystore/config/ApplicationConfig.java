package com.czertainly.provider.entity.keystore.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableJpaAuditing
@PropertySource(value = ApplicationConfig.EXTERNAL_PROPERTY_SOURCE, ignoreResourceNotFound = true)
public class ApplicationConfig {
    private static final Logger logger = LoggerFactory.getLogger(ApplicationConfig.class);

    public static final String EXTERNAL_PROPERTY_SOURCE =
            "file:${czertainly-keystore-entity-provider.config.dir:/etc/czertainly-keystore-entity-provider}/czertainly-keystore-entity-provider.properties";
}
