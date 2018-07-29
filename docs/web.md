# Create a File Info scan micro-service :new: :construction:

```bash
$ docker run -d -p 3993:3993 malice/virustotal web

INFO[0000] web service listening on port :3993
```

## Why?

You can share access to your Private API key without sharing your **PRIVATE** API key :wink:

## Now you can perform scans like so

```bash
$ http -f localhost:3993/lookup hash@befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408
```

> **NOTE:** I am using **httpie** to POST to the malice micro-service

```bash
HTTP/1.1 200 OK
Content-Length: 124
Content-Type: application/json; charset=UTF-8
Date: Sat, 21 Jan 2017 05:39:29 GMT

{
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
```
