package com.czertainly.provider.entity.keystore.config;

import org.apache.sshd.client.SshClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SshClientConfig {

    @Bean
    public SshClient sshClient() {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        return client;
    }
}
