REPO=malice-plugins/virustotal
ORG=malice
NAME=virustotal
VERSION=$(shell cat VERSION)

all: build size tag test

build:
	docker build -t $(ORG)/$(NAME):$(VERSION) .

size:
	sed -i.bu 's/docker image-.*-blue/docker image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION))-blue/' README.md

.PHONY: tag
tag:
	docker tag $(ORG)/$(NAME):$(VERSION) $(ORG)/$(NAME):latest

tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

test: check-env
	@docker run --rm $(ORG)/$(NAME):$(VERSION) --help
	@docker run --rm $(ORG)/$(NAME):$(VERSION) -V --api ${MALICE_VT_API} lookup 669f87f2ec48dce3a76386eec94d7e3b | jq . > docs/results.json
	cat docs/results.json | jq .
	@echo "===> Test lookup found"
	@docker run --rm $(ORG)/$(NAME):$(VERSION) --api ${MALICE_VT_API} lookup -t 669f87f2ec48dce3a76386eec94d7e3b | tee docs/SAMPLE.md
	@echo "===> Test lookup not found"
	@docker run --rm $(ORG)/$(NAME):$(VERSION) --api ${MALICE_VT_API} lookup -t 669f87f2ec48dce3a76386eec94d7ecc | tee -a docs/NOT_FOUND_SAMPLE.md

check-env:
ifndef MALICE_VT_API
    export MALICE_VT_API=2539516d471d7beb6b28a720d7a25024edc0f7590d345fc747418645002ac47b
endif

circle:
	http https://circleci.com/api/v1.1/project/github/${REPO} | jq '.[0].build_num' > .circleci/build_num
	http "$(shell http https://circleci.com/api/v1.1/project/github/${REPO}/$(shell cat .circleci/build_num)/artifacts${CIRCLE_TOKEN} | jq '.[].url')" > .circleci/SIZE
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell cat .circleci/SIZE)-blue/' README.md

.PHONY: build size tags test circle
