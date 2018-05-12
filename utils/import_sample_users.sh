#!/bin/bash

sqlite3 ctf.db 'INSERT INTO users (id, username, email, isAdmin, isHidden, password, ip) values (1, "admin", "admin@admin.com", 1, 1, "pbkdf2:sha1:1000$o7lXRO3w$25007fe0da209c98ed251b91ba9e6717a3ff967a", "192.168.1.1")'
sqlite3 ctf.db 'INSERT INTO users (id, username, email, isAdmin, isHidden, password, ip) values (2, "ayam", "ayam@ayam.com", 0, 0, "pbkdf2:sha1:1000$DaVXViH7$b0ba9ef7b659f3fc1cf6b98808a013f4b7c23e39", "192.168.1.177")'
sqlite3 ctf.db 'INSERT INTO users (id, username, email, isAdmin, isHidden, password, ip) values (3, "itik", "ayam@ayam.com", 0, 0, "pbkdf2:sha1:1000$XcOR46En$b7e92203cee48bec0322cdabbaed568271c0f763", "192.168.1.2")'
