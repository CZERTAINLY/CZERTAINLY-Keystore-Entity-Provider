package com.czertainly.provider.entity.keystore.service.impl;

import com.czertainly.api.model.common.AttributeDefinition;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.provider.entity.keystore.AttributeConstants;
import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;
import com.czertainly.provider.entity.keystore.enums.AuthenticationType;
import com.czertainly.provider.entity.keystore.service.SshService;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.scp.ScpClient;
import org.apache.sshd.client.scp.ScpClientCreator;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class SshServiceImpl implements SshService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public static final int SSH_PORT = 22;
    public static final int SSH_DEFAULT_TIMEOUT = 30;

    @Autowired
    public void setSshClient(SshClient sshClient) {
        this.sshClient = sshClient;
    }

    SshClient sshClient;

    @Override
    public String runRemoteCommand(String command, EntityInstance entity) {
        String host = entity.getHost();

        List<AttributeDefinition> attributes = AttributeDefinitionUtils.deserialize(entity.getCredentialData());
        String username = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_USERNAME, attributes);
        if (entity.getAuthenticationType().equals(AuthenticationType.BASIC)) {
            String password = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_PASSWORD, attributes);
        }
        //else if (entity.getAuthenticationType().equals(AuthenticationType.SSH)) {
            // TODO
        //}

        try (ClientSession session = sshClient.connect(username, host, SSH_PORT)
                .verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS).getSession()) {

            session.addPasswordIdentity(AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_PASSWORD, attributes));
            session.auth().verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS);

            try (ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
                 ClientChannel channel = session.createChannel(Channel.CHANNEL_EXEC, command)) {

                channel.setOut(responseStream);
                try {
                    channel.open().verify(30, TimeUnit.SECONDS);
                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TimeUnit.SECONDS.toMillis(30));
                    String responseString = new String(responseStream.toByteArray());
                    return responseString;
                } finally {
                    channel.close(false);
                }


            } catch (IOException e) {
                logger.debug("Failed to initiate SSH channel.", e);
                throw new IllegalStateException("Failed to initiate SSH channel.", e);
            }
        } catch (IOException e) {
            logger.debug("Failed to initiate SSH session.", e);
            throw new IllegalStateException("Failed to initiate SSH session.", e);
        }
    }

    @Override
    public void uploadFile(EntityInstance entity, String source, String destination) {
        String host = entity.getHost();

        List<AttributeDefinition> attributes = AttributeDefinitionUtils.deserialize(entity.getCredentialData());
        String username = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_USERNAME, attributes);
        if (entity.getAuthenticationType().equals(AuthenticationType.BASIC)) {
            String password = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_PASSWORD, attributes);
        }
        //else if (entity.getAuthenticationType().equals(AuthenticationType.SSH)) {
            // TODO
        //}

        try (ClientSession session = sshClient.connect(username, host, SSH_PORT)
                .verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS).getSession()) {

            session.addPasswordIdentity(AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_PASSWORD, attributes));
            session.auth().verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS);

            ScpClientCreator creator = ScpClientCreator.instance();
            ScpClient client = creator.createScpClient(session);

            client.upload(source, destination);

        } catch (IOException e) {
            logger.debug("Failed to initiate SSH session.", e);
            throw new IllegalStateException("Failed to initiate SSH session.", e);
        }
    }

    @Override
    public void downloadFile(EntityInstance entity, String remote, String local) {
        String host = entity.getHost();

        List<AttributeDefinition> attributes = AttributeDefinitionUtils.deserialize(entity.getCredentialData());
        String username = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_USERNAME, attributes);
        if (entity.getAuthenticationType().equals(AuthenticationType.BASIC)) {
            String password = AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_PASSWORD, attributes);
        }
        //else if (entity.getAuthenticationType().equals(AuthenticationType.SSH)) {
            // TODO
        //}

        try (ClientSession session = sshClient.connect(username, host, SSH_PORT)
                .verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS).getSession()) {

            session.addPasswordIdentity(AttributeDefinitionUtils.getAttributeValue(AttributeConstants.ATTRIBUTE_PASSWORD, attributes));
            session.auth().verify(SSH_DEFAULT_TIMEOUT, TimeUnit.SECONDS);

            ScpClientCreator creator = ScpClientCreator.instance();
            ScpClient client = creator.createScpClient(session);

            client.download(remote, local);

        } catch (IOException e) {
            logger.debug("Failed to initiate SSH session.", e);
            throw new IllegalStateException("Failed to initiate SSH session.", e);
        }
    }
}
