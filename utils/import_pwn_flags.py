#!/usr/bin/env python

import dataset
import json

config_str = open('config.json', 'rb').read()
config = json.loads(config_str)

db = dataset.connect(config['db'])

timestamp = 78634587365
ip = "192.168.1.1"

for i in range(1, 5):
    flag = dict(id=i, user_id=i, flag='ayam'+str(i), score=(i*100), timestam=timestamp, ip=ip)
    db['services'].insert(flag)
