# POST results to a webhook

```bash
$ docker run -v `pwd`:/malware:ro --rm \
             -e MALICE_ENDPOINT="https://malice.io:31337/scan/file" malice/virustotal lookup --callback HASH
```

## `callback`

If you supply a callback URL the JSON will also be sent to your BIG database backend for "caching" :sunglasses:
