package com.czertainly.provider.entity.keystore;

import org.apache.commons.lang3.StringUtils;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class SshTest {

    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final int SSH_PORT = 8001;

    private SshServer sshd;

    @BeforeEach
    public void prepare() throws IOException {
        setupSSHServer();
    }

    @AfterEach
    public void cleanup() {
        try {
            sshd.stop(true);
        } catch (Exception e) {
            // do nothing
        }
    }

    private void setupSSHServer() throws IOException {
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(SSH_PORT);
        sshd.setShellFactory(new ProcessShellFactory("/bin/sh", "-i", "-l"));
        //sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get(new File("hostkey.ser").getAbsolutePath())));
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPasswordAuthenticator((username, password, session) -> StringUtils.equals(username, USERNAME) && StringUtils.equals(password, PASSWORD));
        sshd.start();
    }

    @Test
    public void testBasicAuthentication() {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        String host = "localhost";

        try (ClientSession session = client.connect(USERNAME, host, SSH_PORT)
                .verify(30, TimeUnit.SECONDS).getSession()) {

            session.addPasswordIdentity(PASSWORD);
            session.auth().verify(30, TimeUnit.SECONDS);

            Assertions.assertNotNull(session);

        } catch (IOException e) {
            // TODO
            e.printStackTrace();
            throw new IllegalStateException("Failed to initialize session.", e);
        }
    }

//    @Test
//    public void testLsCommand() throws Exception {
//        SshClient client = SshClient.setUpDefaultClient();
//        client.start();
//
//        String host = "localhost";
//
//        try (ClientSession session = client.connect(USERNAME, host, 22)
//                .verify(30, TimeUnit.SECONDS).getSession()) {
//
//            session.addPasswordIdentity(PASSWORD);
//            session.auth().verify(30, TimeUnit.SECONDS);
//
//            try (ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
//                 ClientChannel channel = session.createChannel(Channel.CHANNEL_EXEC, "ls /tmp")) {
//                channel.setOut(responseStream);
//                try {
//                    channel.open().verify(30, TimeUnit.SECONDS);
//                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED),
//                            TimeUnit.SECONDS.toMillis(30));
//                    String responseString = new String(responseStream.toByteArray());
//                    System.out.println(responseString);
//                } finally {
//                    channel.close(false);
//                }
//            }
//
//            Assertions.assertNotNull(session);
//
//        } catch (IOException e) {
//            // TODO
//            e.printStackTrace();
//            throw new IllegalStateException("Failed to initialize session.", e);
//        }
//    }
}
