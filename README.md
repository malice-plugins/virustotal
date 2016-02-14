![VT logo](https://raw.githubusercontent.com/maliceio/malice-virustotal/master/logo.png)
# malice-virustotal

[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)
[![Docker Stars](https://img.shields.io/docker/stars/malice/virustotal.svg)][hub]
[![Docker Pulls](https://img.shields.io/docker/pulls/malice/virustotal.svg)][hub]
[![Image Size](https://img.shields.io/imagelayers/image-size/malice/virustotal/latest.svg)](https://imagelayers.io/?images=malice/virustotal:latest)
[![Image Layers](https://img.shields.io/imagelayers/layers/malice/virustotal/latest.svg)](https://imagelayers.io/?images=malice/virustotal:latest)

Malice VirusTotal Plugin

This repository contains a **Dockerfile** of **Malice VirusTotal Plugin** for [Docker](https://www.docker.io/)'s [trusted build](https://index.docker.io/u/malice/virustotal/) published to the public [DockerHub](https://index.docker.io/).

### Dependencies

* [gliderlabs/alpine:3.3](https://index.docker.io/_/gliderlabs/alpine/)


### Installation

1. Install [Docker](https://www.docker.io/).
2. Download [trusted build](https://hub.docker.com/r/malice/virustotal/) from public [DockerHub](https://hub.docker.com): `docker pull malice/virustotal`

### Usage

    docker run -it --rm malice/virustotal HASH

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
    "infected": true,
    "result": "Eicar-Test-Signature",
    "engine": "0.99",
    "known": "4213581",
    "updated": "20160213"
  }
}
```
### Sample Output STDOUT (Markdown Table):
---
#### virustotal
| Infected | Result               | Engine | Updated  |
| -------- | -------------------- | ------ | -------- |
| true     | Eicar-Test-Signature | 0.99   | 20160213 |
---
### To Run on OSX
 - Install [Homebrew](http://brew.sh)

```bash
$ brew install caskroom/cask/brew-cask
$ brew cask install virtualbox
$ brew install docker
$ brew install docker-machine
$ docker-machine create --driver virtualbox malice
$ eval $(docker-machine env malice)
```

### Documentation

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/maliceio/malice-av/issues/new) and I'll get right on it.

### Credits

### License
MIT Copyright (c) 2016 **blacktop**

[hub]: https://hub.docker.com/r/malice/virustotal/
