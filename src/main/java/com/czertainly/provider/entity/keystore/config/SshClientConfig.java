package com.czertainly.provider.entity.keystore.config;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.nio.file.Paths;

@Configuration
public class SshClientConfig {

    // TODO: configuration properties for the SSH client from application.yml

    @Bean
    public SshClient sshClient() {
        SshClient client = SshClient.setUpDefaultClient(); // using the default configuration of the client

        Path knownHostsPath = Paths.get(System.getProperty("user.home"), ".ssh", "known_hosts");
        KnownHostsServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, knownHostsPath);

        client.setServerKeyVerifier(verifier);
        client.start();

        return client;
    }
}
