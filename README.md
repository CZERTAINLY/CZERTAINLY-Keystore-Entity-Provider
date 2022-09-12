# CZERTAINLY Keystore Entity Provider

> This repository is part of the commercial open-source project CZERTAINLY, but the connector is available under subscription. You can find more information about the project at [CZERTAINLY](https://github.com/3KeyCompany/CZERTAINLY) repository, including the contribution guide.

Keystore Entity Provider `Connector` is the implementation of the following `Function Groups` and `Kinds`:

| Function Group | Kind |
| --- | --- |
| `Entity Provider` | `Keystore` |

Keystore Entity Provider implements automation of certificate management related tasks on the software keystores:
- JKS
- PKCS#12

It is compatible with the `Entity Ptovider` interface. This entity provider utilizes the SSH authorized connection with the servers and provider the location configuration of the keystores with access to generate and manipulate the content.

Keystore Entity Provider `Connector` allows you to perform the following operations:
- Register servers (with SSH access)
- Register keystore locations
- Publish certificate to the keystore
- Generate key pair and request certificate (CSR)
- Remove certificates (and keys) from the keystore
- Automatically renew certificates in the keystore

## Database requirements

Keystore Entity Provider `Connector` requires the PostgreSQL database to store the data.

## Short Process Description

Keystore Entity Provider `Connector` provides access to the keystore locations on the remote servers. Multiple locations on one server are supported. The `Connector` can create multiple `Entities` and automate the certificate lifecycle on associated locations.

The certificate operations are provided by the CZERTAINLY `Core` platform consistently across `Entity Providers`.

To know more about the `Core`, refer to [CZERTAINLY Core](https://github.com/3KeyCompany/CZERTAINLY-Core)

### `Entity` attributes

The attributes for creating a new `Entity` includes:
- Hostname / IP Address of the `Entity`
- Type of the authentication
- Credential

### `Location` attributes

The attributes for creating a new `Location` includes:
- Keystore Path
- Keystore Password
- Keystore Type

## Interfaces

Keystore Entity Provider implements `Entity Provider` interfaces. To learn more about the interfaces and end points, refer to the [CZERTAINLY Interfaces](https://github.com/3KeyCompany/CZERTAINLY-Interfaces).

For more information, please refer to the [CZERTAINLY documentation](https://docs.czertainly.com).

## Docker container

Keystore Entity Provider `Connector` is provided as a Docker container. Use the `docker pull harbor.3key.company/czertainly/czertainly-keystore-entity-provider:tagname` to pull the required image from the repository. It can be configured using the following environment variables:

| Variable | Description | Required | Default value |
| --- | --- | --- | --- |
| `JDBC_URL` | JDBC URL for database access | Yes | N/A |
| `JDBC_USERNAME` | Username to access the database | Yes | N/A |
| `JDBC_PASSWORD` | Password to access the database | Yes | N/A |
| `DB_SCHEMA` | Database schema to use | No | ejbca |
| `PORT` | Port where the service is exposed | No | 8080 |