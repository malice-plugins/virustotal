FROM gliderlabs/alpine

MAINTAINER blacktop, https://github.com/blacktop

COPY . /go/src/github.com/maliceio/malice-virustotal
RUN apk-install ca-certificates
RUN apk-install -t build-deps go git mercurial \
  && set -x \
  && echo "Building info Go binary..." \
  && cd /go/src/github.com/maliceio/malice-virustotal \
  && export GOPATH=/go \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/virustotal \
  && rm -rf /go \
  && apk del --purge build-deps

WORKDIR /malware

ENTRYPOINT ["/bin/virustotal"]

CMD ["--help"]
