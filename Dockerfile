FROM malice/alpine

MAINTAINER blacktop, https://github.com/blacktop

COPY . /go/src/github.com/maliceio/malice-virustotal
RUN apk-install ca-certificates
RUN apk-install -t .build-deps \
                    build-base \
                    mercurial \
                    musl-dev \
                    openssl \
                    bash \
                    wget \
                    git \
                    gcc \
                    go \
  && set -x \
  && cd /tmp \
  && wget https://raw.githubusercontent.com/maliceio/go-plugin-utils/master/scripts/upgrade-alpine-go.sh \
  && chmod +x upgrade-alpine-go.sh \
  && ./upgrade-alpine-go.sh \
  && echo "Building virustotal Go binary..." \
  && cd /go/src/github.com/maliceio/malice-virustotal \
  && export GOPATH=/go \
  && export PATH=$GOPATH/bin:/usr/local/go/bin:$PATH \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/virustotal \
  && rm -rf /go /usr/local/go /usr/lib/go /tmp/* \
  && apk del --purge .build-deps

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","/sbin/tini","--","virustotal"]

CMD ["--help"]
