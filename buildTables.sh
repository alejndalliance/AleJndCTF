#!/bin/bash

mkdir static/files

sqlite3 ctf.db 'CREATE TABLE categories ( id INTEGER PRIMARY KEY, name TEXT )'

# Users
sqlite3 ctf.db 'CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT, isAdmin BOOLEAN, isHidden BOOLEAN, password TEXT)'

# Jeopardy
sqlite3 ctf.db 'CREATE TABLE tasks (id INTEGER PRIMARY KEY, name TEXT, desc TEXT, file TEXT, flag TEXT, score INT, category INT, FOREIGN KEY(category) REFERENCES categories(id) ON DELETE CASCADE)'
sqlite3 ctf.db 'CREATE TABLE flags (task_id INTEGER, user_id INTEGER, score INTEGER, timestamp BIGINT, ip TEXT, PRIMARY KEY (task_id, user_id), FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);'

# Attack and Defense
sqlite3 ctf.db 'CREATE TABLE services (id INTEGER, user_id INTEGER, name TEXT, desc TEXT, flag TEXT, score INT, PRIMARY KEY (id, user_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)'
sqlite3 ctf.db 'CREATE TABLE pwn_flags (service_id INTEGER, user_id INTEGER, score INTEGER, timestamp BIGINT, ip TEXT, PRIMARY KEY (service_id, user_id) FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)'
