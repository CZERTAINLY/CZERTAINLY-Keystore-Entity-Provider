package com.czertainly.provider.entity.keystore.dao.entity;

import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.connector.entity.EntityInstanceDto;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.provider.entity.keystore.enums.AuthenticationType;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.*;

@Entity
@Table(name = "entity_instance")
@EntityListeners(AuditingEntityListener.class)
public class EntityInstance {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "entity_instance_seq")
    @SequenceGenerator(name = "entity_instance_seq", sequenceName = "entity_instance_id_seq", allocationSize = 1)
    private Long id;

    @Column(name = "uuid")
    private String uuid;

    @Column(name = "name")
    private String name;

    @Column(name = "host")
    private String host;

    @Column(name = "auth_type")
    private AuthenticationType authenticationType;

    @Column(name = "credential_uuid")
    private String credentialUuid;

    @Basic(fetch = FetchType.LAZY)
    @Column(name = "credential_data", length = 40960)
    private String credentialData;

    @Column(name="attributes")
    private String attributes;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public AuthenticationType getAuthenticationType() { return authenticationType; }

    public void setAuthenticationType(AuthenticationType authenticationType) { this.authenticationType = authenticationType; }

    public String getCredentialData() {
        return credentialData;
    }

    public void setCredentialData(String credentialData) {
        this.credentialData = credentialData;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getCredentialUuid() {
        return credentialUuid;
    }

    public void setCredentialUuid(String credentialUuid) {
        this.credentialUuid = credentialUuid;
    }

    public String getAttributes() {
        return attributes;
    }

    public void setAttributes(String attributes) {
        this.attributes = attributes;
    }

    public EntityInstanceDto mapToDto() {
        EntityInstanceDto dto = new EntityInstanceDto();
        dto.setUuid(this.uuid);
        dto.setName(this.name);

        if (attributes != null) {
            dto.setAttributes(AttributeDefinitionUtils.deserialize(attributes, BaseAttribute.class));
        }

        return dto;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EntityInstance that = (EntityInstance) o;
        return new EqualsBuilder().append(id, that.id).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(id).toHashCode();
    }
}
