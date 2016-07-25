NAME=virustotal
VERSION=$(shell cat VERSION)
DEV_RUN_OPTS ?= consul:

dev:
	docker build -f Dockerfile.dev -t $(NAME):dev .
	docker run --rm \
		-v /var/run/docker.sock:/tmp/docker.sock \
		$(NAME):dev /bin/registrator $(DEV_RUN_OPTS)

build:
	mkdir -p build
	docker build -t $(NAME):$(VERSION) .
	SIZE=$(docker images --format "{{.Size}}" virustotal)
	sed -i 's/docker image-.*-blue/docker image-'${SIZE}'-blue/g' README.md
	docker save $(NAME):$(VERSION) | gzip -9 > build/$(NAME)_$(VERSION).tgz

release:
	rm -rf release && mkdir release
	go get github.com/progrium/gh-release/...
	cp build/* release
	gh-release create maliceio/malice-$(NAME) $(VERSION) \
		$(shell git rev-parse --abbrev-ref HEAD) $(VERSION)
	glu hubtag maliceio/malice-$(NAME) $(VERSION)

circleci:
	rm -f ~/.gitconfig
	go get -u github.com/gliderlabs/glu
	glu circleci

.PHONY: build release
