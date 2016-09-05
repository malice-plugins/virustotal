![VT logo](https://raw.githubusercontent.com/maliceio/malice-virustotal/master/logo.png)

malice-virustotal
=================

[![Circle CI](https://circleci.com/gh/maliceio/malice-virustotal.png?style=shield)](https://circleci.com/gh/maliceio/malice-virustotal) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/virustotal.svg)](https://hub.docker.com/r/malice/virustotal/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/virustotal.svg)](https://hub.docker.com/r/malice/virustotal/) [![Docker Image](https://img.shields.io/badge/docker image-19.63 MB-blue.svg)](https://hub.docker.com/r/malice/virustotal/)

Malice VirusTotal Plugin

This repository contains a **Dockerfile** of the [VirusTotal](https://virustotal.com) malice plugin **malice/virustotal**.

> *NOTE:* Currently only supports Public API

### Dependencies

-	[malice/alpine:tini](https://hub.docker.com/r/malice/alpine/)

### Installation

1.	Install [Docker](https://www.docker.io/).
2.	Download [trusted build](https://hub.docker.com/r/malice/virustotal/) from public [DockerHub](https://hub.docker.com): `docker pull malice/virustotal`

### Usage

```
docker run --rm malice/virustotal --api APIKEY lookup HASH
```

```bash
Usage: virustotal [OPTIONS] COMMAND [arg...]

Malice VirusTotal Plugin

Version: v0.1.0, BuildTime: 20160214

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --table, -t	output as Markdown table
  --post, -p	POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x	proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --api 	VirusTotal API key [$MALICE_VT_API]
  --help, -h	show help
  --version, -v	print the version

Commands:
  scan		Upload binary to VirusTotal for scanning
  lookup	Get file hash scan report
  help		Shows a list of commands or help for one command

Run 'virustotal COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

### Sample Output JSON:

```json
{
  "virustotal": {
    "scans": {
      "McAfee": {
        "detected": true,
        "version": "6.0.6.653",
        "result": "BackDoor-CSB",
        "update": "20160214"
      },
      "F-Prot": {
        "detected": true,
        "version": "4.7.1.166",
        "result": "W32/Trojan.AAWD",
        "update": "20160214"
      },
      "Symantec": {
        "detected": true,
        "version": "20151.1.0.32",
        "result": "W32.Lecna.D",
        "update": "20160214"
      },
      "ESET-NOD32": {
        "detected": true,
        "version": "13027",
        "result": "a variant of Win32/Lecna.W",
        "update": "20160214"
      },
      "ClamAV": {
        "detected": true,
        "version": "0.98.5.0",
        "result": "Win.Trojan.Backspace",
        "update": "20160214"
      },
      "Kaspersky": {
        "detected": true,
        "version": "15.0.1.13",
        "result": "Backdoor.Win32.Lecna.ab",
        "update": "20160214"
      },
      "BitDefender": {
        "detected": true,
        "version": "7.2",
        "result": "Backdoor.Lecna.AB",
        "update": "20160214"
      },
      "Comodo": {
        "detected": true,
        "version": "24205",
        "result": "Backdoor.Win32.Lecna.AB",
        "update": "20160214"
      },
      <SNIP...>
      "F-Secure": {
        "detected": true,
        "version": "11.0.19100.45",
        "result": "Backdoor.Lecna.AB",
        "update": "20160213"
      },
      "DrWeb": {
        "detected": true,
        "version": "7.0.17.11230",
        "result": "BackDoor.Dizhi",
        "update": "20160214"
      },
      "Sophos": {
        "detected": true,
        "version": "4.98.0",
        "result": "Troj/Lecna-Q",
        "update": "20160214"
      },
      "Avira": {
        "detected": true,
        "version": "8.3.3.2",
        "result": "WORM/Rbot.Gen",
        "update": "20160214"
      },
      "AVG": {
        "detected": true,
        "version": "16.0.0.4522",
        "result": "Win32/DH{YQMT?}",
        "update": "20160214"
      }
    },
    "scan_id": "befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408-1455475165",
    "sha1": "6b82f126555e7644816df5d4e4614677ee0bda5c",
    "resource": "befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408",
    "response_code": 1,
    "scan_date": "2016-02-14 18:39:25",
    "permalink": "https://www.virustotal.com/file/befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408/analysis/1455475165/",
    "verbose_msg": "Scan finished, information embedded",
    "total": 54,
    "positives": 46,
    "sha256": "befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408",
    "md5": "669f87f2ec48dce3a76386eec94d7e3b"
  }
}
```

### Sample Output STDOUT (Markdown Table):

---

#### virustotal

| Ratio | Link                          | API    | Scanned                |
|-------|-------------------------------|--------|------------------------|
| 85%   | [link](http://bit.ly/1ThieJ6) | Public | Sun 2016Feb14 14:00:50 |

---

### To write results to [RethinkDB](https://rethinkdb.com)

```bash
$ docker volume create --name malice
$ docker run -d -p 28015:28015 -p 8080:8080 -v malice:/data --name rethink rethinkdb
$ docker run --rm --link rethink malice/virustotal --api APIKEY lookup HASH
```

### Documentation

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/maliceio/malice-virustotal/issues/new) and I'll get right on it.

### ToDo

-	[ ] Add docs like [registrator](http://gliderlabs.com/registrator/latest/#getting-registrator)
-	[ ] Break out common plugin components into a golang package

### License

MIT Copyright (c) 2016 **blacktop**
