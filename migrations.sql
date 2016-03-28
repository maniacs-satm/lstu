-- 1 up
CREATE TABLE IF NOT EXISTS lstu (
    short text PRIMARY KEY,
    url text,
    counter integer,
    timestamp integer
);
CREATE TABLE IF NOT EXISTS sessions (
    token text PRIMARY KEY,
    until integer
);
-- 1 down
DROP TABLE sessions;
DROP TABLE lstu;
