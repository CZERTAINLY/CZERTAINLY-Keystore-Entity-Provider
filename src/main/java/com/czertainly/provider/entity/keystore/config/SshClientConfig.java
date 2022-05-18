package com.czertainly.provider.entity.keystore.config;

import org.apache.sshd.client.SshClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SshClientConfig {

    // TODO: configuration properties for the SSH client from application.yml

    @Bean
    public SshClient sshClient() {
        SshClient client = SshClient.setUpDefaultClient(); // using the default configuration of the client
        client.start();

        return client;
    }
}
