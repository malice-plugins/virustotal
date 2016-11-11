NAME=virustotal
VERSION=$(shell cat VERSION)
DEV_RUN_OPTS ?= --api 2539516d471d7beb6b28a720d7a25024edc0f7590d345fc747418645002ac47b lookup 669f87f2ec48dce3a76386eec94d7e3b

dev:
	docker build -f Dockerfile.dev -t $(NAME):dev .
	docker run --rm $(NAME):dev $(DEV_RUN_OPTS)

build:
	docker build -t $(NAME):$(VERSION) .
	sed -i.bu 's/docker image-.*-blue/docker image-$(shell docker images --format "{{.Size}}" $(NAME):$(VERSION))-blue/g' README.md

release:
	rm -rf release && mkdir release
	go get github.com/progrium/gh-release/...
	cp build/* release
	gh-release create maliceio/malice-$(NAME) $(VERSION) \
		$(shell git rev-parse --abbrev-ref HEAD) $(VERSION)
	# glu hubtag maliceio/malice-$(NAME) $(VERSION)

circleci:
	rm -f ~/.gitconfig
	go get -u github.com/gliderlabs/glu
	glu circleci

.PHONY: build release
