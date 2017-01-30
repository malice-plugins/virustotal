REPO=malice
NAME=virustotal
VERSION=$(shell cat VERSION)

all: build size test

build:
	docker build -t $(REPO)/$(NAME):$(VERSION) .

size:
	sed -i.bu 's/docker image-.*-blue/docker image-$(shell docker images --format "{{.Size}}" $(REPO)/$(NAME):$(VERSION))-blue/' README.md

tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(REPO)/$(NAME)

test:
	docker run --rm $(REPO)/$(NAME):$(VERSION) --help
	docker run --rm $(REPO)/$(NAME):$(VERSION) -V --api 2539516d471d7beb6b28a720d7a25024edc0f7590d345fc747418645002ac47b lookup 669f87f2ec48dce3a76386eec94d7e3b > results.json
	cat results.json | jq .
	cat results.json | jq -r .$(NAME).markdown

.PHONY: build size tags test
