CREATE TABLE issued_refresh_tokens (
    sub     uuid REFERENCES users(id) NOT NULL,
    jti     uuid PRIMARY KEY NOT NULL,
    exp     TIMESTAMPTZ NOT NULL,
    iat     TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE issued_refresh_tokens_blacklist (
    jti     uuid PRIMARY KEY NOT NULL,
    exp     TIMESTAMPTZ NOT NULL
);

CREATE TABLE users (
    id              UUID PRIMARY KEY NOT NULL,
    secondary_id    UUID UNIQUE NOT NULL,
    firstname       varchar(256) NOT NULL,
    lastname        varchar(256) NOT NULL,
    email           varchar(512) UNIQUE NOT NULL,
    member_since    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    password        VARCHAR NOT NULL
);

CREATE TABLE deleted_users (
    id              uuid PRIMARY KEY NOT NULL,
    firstname       varchar(256) NOT NULL,
    lastname        varchar(256) NOT NULL,
    email           varchar(512) UNIQUE NOT NULL,
    member_since    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    password        VARCHAR NOT NULL
);

CREATE TABLE unverified_users (
    id                  uuid UNIQUE NOT NULL,
    email               varchar(512) UNIQUE NOT NULL,
    verification_code   char(6) NOT NULL
);