FROM malice/alpine

LABEL maintainer "https://github.com/blacktop"

LABEL malice.plugin.repository = "https://github.com/malice-plugins/shadow-server.git"
LABEL malice.plugin.category="intel"
LABEL malice.plugin.mime="hash"
LABEL malice.plugin.docker.engine="*"

COPY . /go/src/github.com/maliceio/malice-virustotal
RUN apk --update add --no-cache ca-certificates
RUN apk --update add --no-cache -t .build-deps build-base \
  mercurial \
  musl-dev \
  openssl \
  bash \
  wget \
  git \
  gcc \
  dep \
  go \
  && echo "===> Building virustotal Go binary..." \
  && cd /go/src/github.com/maliceio/malice-virustotal \
  && export GOPATH=/go \
  && go version \
  && dep ensure \
  && go build -ldflags "-X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/virustotal \
  && rm -rf /go /usr/local/go /usr/lib/go /tmp/* /var/cache/apk/* /root/go \
  && apk del --purge .build-deps

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","/sbin/tini","--","virustotal"]
CMD ["--help"]
