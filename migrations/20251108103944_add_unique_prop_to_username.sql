-- Add migration script here
ALTER TABLE users
ADD CONSTRAINT users_username_unique UNIQUE (username);