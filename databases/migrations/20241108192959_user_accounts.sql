-- +goose Up
-- +goose StatementBegin
CREATE TABLE user_accounts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name VARCHAR(100) UNIQUE,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255),
    phone_number VARCHAR(25),
    email VARCHAR(100) UNIQUE
);
-- default value when database initializes
INSERT INTO user_accounts (user_name, first_name, last_name, phone_number, email)
VALUES ('johndoe', 'John', 'Doe', '123-456-7890', 'johndoe@example.com');

INSERT INTO user_accounts (user_name, first_name, last_name, phone_number, email)
VALUES ('janedoe', 'Jane', 'Doe', '987-654-3210', 'janedoe@example.com');

INSERT INTO user_accounts (user_name, first_name, last_name, phone_number, email)
VALUES ('alice_smith', 'Alice', 'Smith', '555-123-4567', 'alice.smith@example.com');

INSERT INTO user_accounts (user_name, first_name, last_name, phone_number, email)
VALUES ('bob_jones', 'Bob', 'Jones', '444-777-8888', 'bob.jones@example.com');

INSERT INTO user_accounts (user_name, first_name, last_name, phone_number, email)
VALUES ('charlie_brown', 'Charlie', 'Brown', '333-444-5555', 'charlie.brown@example.com');

CREATE TABLE users (
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    refresh_token TEXT,
    PRIMARY KEY (email)
);
-- INSERT INTO users (email, password) VALUES ('john.doe@example.com', 'password123');
-- INSERT INTO users (email, password) VALUES ('jane.smith@example.com', 'securepass456');
-- INSERT INTO users (email, password) VALUES ('sam.wilson@example.com', 'mysecret789');
-- INSERT INTO users (email, password) VALUES ('emma.brown@example.com', 'emmapass321');
-- INSERT INTO users (email, password) VALUES ('mike.jones@example.com', 'supersecure654');

CREATE TABLE users_github (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    github_id BIGINT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    avatar_url TEXT,
    github_username TEXT UNIQUE NOT NULL,
    github_access_token TEXT,
    refresh_token TEXT
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE users;
DROP TABLE user_accounts;
DROP TABLE users_github;
-- +goose StatementEnd
