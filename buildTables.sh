#!/bin/bash

STORAGE=static/files

if [ ! -d  $STORAGE ]; then
    echo 'Creating storage directory.'
    mkdir static/files
fi

sqlite3 ctf.db 'CREATE TABLE categories ( id INTEGER PRIMARY KEY, name TEXT )'

# Users
sqlite3 ctf.db 'CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT, isAdmin BOOLEAN, isHidden BOOLEAN, password TEXT)'

# Jeopardy
sqlite3 ctf.db 'CREATE TABLE tasks (id INTEGER PRIMARY KEY, name TEXT, desc TEXT, file TEXT, flag TEXT, score INT, category INT, FOREIGN KEY(category) REFERENCES categories(id) ON DELETE CASCADE)'
sqlite3 ctf.db 'CREATE TABLE flags (task_id INTEGER, user_id INTEGER, score INTEGER, timestamp BIGINT, ip TEXT, PRIMARY KEY (task_id, user_id), FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);'

# Attack and Defense
sqlite3 ctf.db 'CREATE TABLE services (id INTEGER, user_id INTEGER, flag TEXT, score INTEGER, timestamp BIGINT, ip TEXT, PRIMARY KEY (id, user_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)'
sqlite3 ctf.db 'CREATE TABLE pwn (service_id INTEGER, user_id INTEGER, target_id INTEGER, score INTEGER, timestamp BIGINT, ip TEXT, PRIMARY KEY (service_id, user_id, target_id))'
sqlite3 ctf.db 'CREATE TABLE pwn_deduct (user_id INTEGER, deduct INTEGER, timestamp BIGINT, PRIMARY KEY (user_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)'

echo 'Done creating tables.'
