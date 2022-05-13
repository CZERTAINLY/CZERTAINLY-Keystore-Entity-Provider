create sequence entity_instance_id_seq start 1 increment 1;

create table entity_instance
(
    id                 int8         not null,
    uuid               varchar(255) not null,
    name               varchar(255),
    credential_uuid    varchar(255),
    credential_data    text,
    attributes         text,
    host               varchar,
    auth_type          varchar,
    primary key (id)
);