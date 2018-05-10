#!/bin/bash

DB=ctf.db

if [ ! -f $DB ]; then
    echo 'Database file is missing.'
    exit
fi

sqlite3 $DB 'DELETE FROM categories'
sqlite3 $DB 'DELETE FROM users'
sqlite3 $DB 'DELETE FROM tasks'
sqlite3 $DB 'DELETE FROM flags'
sqlite3 $DB 'DELETE FROM services'
sqlite3 $DB 'DELETE FROM pwn'
sqlite3 $DB 'DELETE FROM pwn_deduct'

rm -r static/files/*

echo 'Done cleaning up.'
