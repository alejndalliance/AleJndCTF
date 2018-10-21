[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.rawsec.ml/ctf_platforms.html#AleJndCTF)
[![GitHub stars](https://img.shields.io/github/stars/alejndalliance/AleJndCTF.svg)](https://github.com/alejndalliance/AleJndCTF/stargazers)
[![GitHub license](https://img.shields.io/github/license/alejndalliance/AleJndCTF.svg)](https://github.com/alejndalliance/AleJndCTF/blob/master/LICENSE)

AleJndCTF
================

`AleJndCTF` is a fork of another open-source (jeopardy style) CTF platform called the [tinyctf-platform](https://github.com/balidani/tinyctf-platform).
This fork also contains part of the implementations from [internetwache](https://github.com/internetwache/tinyctf-platform) and [gartnera](https://github.com/gartnera/tinyctf-platform) forked version.

#### Jeopardy
![alt text](./utils/jeopardy.png)

#### Attack and Defense
![alt text](./utils/attack.png)

#### Usage

```bash
$ pip install -r requirements.txt
$ ./buildTables.sh
$ python server.py
```
### Docs

Simple documentations at [wiki](https://github.com/alejndalliance/AleJndCTF/wiki)

For Attack and Defense mode. Please refer [here](https://github.com/alejndalliance/AleJndFlag).

#### TODO

```bash
$ cd /path/to/AleJndCTF
$ grep -RE "TODO|FIXME|NOTE" .
```

#### Contact

mohdfakhrizulkifli at gmail dot com.

*Note*: Flask should run on top of a proper web server if you plan to have many players.
