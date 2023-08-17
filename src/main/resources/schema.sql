CREATE TABLE IF NOT EXISTS account (
    username VARCHAR(128) NOT NULL,
    password VARCHAR(256) NOT NULL,
    PRIMARY KEY(username)
);