FROM gliderlabs/alpine

MAINTAINER blacktop, https://github.com/blacktop

# This is the release of https://github.com/hashicorp/docker-base to pull in order
# to provide HashiCorp-built versions of basic utilities like dumb-init and gosu.
ENV DOCKER_BASE_VERSION 0.0.4
ENV DBASE_URL releases.hashicorp.com/docker-base

# Create a malice user and group first so the IDs get set the same way, even as
# the rest of this may change over time.
RUN addgroup malice && \
    adduser -S -G malice malice

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY . /go/src/github.com/maliceio/malice-virustotal
RUN apk-install ca-certificates
RUN apk-install -t build-deps go git mercurial gnupg openssl \
  && set -x \
  && echo "Install hashicorp/docker-base..." \
  && gpg --recv-keys 91A6E7F85D05C65630BEF18951852D87348FFC4C \
  && mkdir -p /tmp/build \
  && cd /tmp/build \
  && wget https://${DBASE_URL}/${DOCKER_BASE_VERSION}/docker-base_${DOCKER_BASE_VERSION}_linux_amd64.zip \
  && wget https://${DBASE_URL}/${DOCKER_BASE_VERSION}/docker-base_${DOCKER_BASE_VERSION}_SHA256SUMS \
  && wget https://${DBASE_URL}/${DOCKER_BASE_VERSION}/docker-base_${DOCKER_BASE_VERSION}_SHA256SUMS.sig \
  && gpg --batch --verify docker-base_${DOCKER_BASE_VERSION}_SHA256SUMS.sig docker-base_${DOCKER_BASE_VERSION}_SHA256SUMS \
  && grep ${DOCKER_BASE_VERSION}_linux_amd64.zip docker-base_${DOCKER_BASE_VERSION}_SHA256SUMS | sha256sum -c \
  && unzip docker-base_${DOCKER_BASE_VERSION}_linux_amd64.zip  \
  && cp bin/gosu bin/dumb-init /bin \
  && mkdir /malware \
  && chown -R malice:malice /malware \
  && chmod +x /usr/local/bin/docker-entrypoint.sh \
  && echo "Building info Go binary..." \
  && cd /go/src/github.com/maliceio/malice-virustotal \
  && export GOPATH=/go \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/virustotal \
  && rm -rf /go /tmp/* \
  && apk del --purge build-deps

WORKDIR /malware

ENTRYPOINT ["docker-entrypoint.sh"]

# ENTRYPOINT ["/bin/virustotal"]

CMD ["virustotal", "--help"]
