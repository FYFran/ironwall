-- Init migration for test app

CREATE TABLE users (
    id SERIAL PRIMARY KEY,           -- AUTOINCREMENT without UUID
    username VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,  -- VULN: plaintext password column
    email VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- VULN: Missing index on foreign key
CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    title TEXT NOT NULL,
    content TEXT
);

-- VULN: GRANT ALL permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_user;

-- VULN: MD5 password hash
UPDATE users SET password = MD5('default_password') WHERE id = 1;

-- VULN: AUTOINCREMENT exposed
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    key_value VARCHAR(64) NOT NULL
);
