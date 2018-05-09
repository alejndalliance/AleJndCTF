#!/usr/bin/env python

import dataset
import json

config_str = open('config.json', 'rb').read()
config = json.loads(config_str)

db = dataset.connect(config['db'])

scores = db.query('''select u.username, ifnull(sum(f.score), 0) as score,
        max(timestamp) as last_submit from users u left join flags f
        on u.id = f.user_id where u.isHidden = 0 group by u.username order by score desc, last_submit asc''')

scores = list(scores)

print json.dumps(scores, indent=4, sort_keys=True)
