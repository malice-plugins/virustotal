FROM malice/alpine

MAINTAINER blacktop, https://github.com/blacktop

COPY . /go/src/github.com/maliceio/malice-virustotal
RUN apk --update add --no-cache ca-certificates
RUN apk --update add --no-cache -t .build-deps \
                                    build-base \
                                    mercurial \
                                    musl-dev \
                                    openssl \
                                    bash \
                                    wget \
                                    git \
                                    gcc \
                                    go \
  && echo "===> Building virustotal Go binary..." \
  && cd /go/src/github.com/maliceio/malice-virustotal \
  && export GOPATH=/go \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/virustotal \
  && rm -rf /go /usr/local/go /usr/lib/go /tmp/* /var/cache/apk/* \
  && apk del --purge .build-deps

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","/sbin/tini","--","virustotal"]
CMD ["--help"]
