REPO=malice-plugins/virustotal
ORG=malice
NAME=virustotal
CATEGORY=intel
VERSION=$(shell cat VERSION)

FOUND_HASH=669f87f2ec48dce3a76386eec94d7e3b
MISSING_HASH=669f87f2ec48dce3a76386eec94d7ecc


all: build size tag test test_markdown

.PHONY: build
build:
	cd $(VERSION); docker build -t $(ORG)/$(NAME):$(VERSION) .

.PHONY: size
size:
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

.PHONY: tag
tag:
	docker tag $(ORG)/$(NAME):$(VERSION) $(ORG)/$(NAME):latest

.PHONY: tags
tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

.PHONY: ssh
ssh:
	@docker run --init -it --rm --entrypoint=bash $(ORG)/$(NAME):$(VERSION)

.PHONY: tar
tar:
	docker save $(ORG)/$(NAME):$(VERSION) -o $(NAME).tar

.PHONY: check_env
check_env:
ifndef MALICE_VT_API
    export MALICE_VT_API=2539516d471d7beb6b28a720d7a25024edc0f7590d345fc747418645002ac47b
endif

.PHONY: start_elasticsearch
start_elasticsearch:
ifeq ("$(shell docker inspect -f {{.State.Running}} elasticsearch)", "true")
	@echo "===> elasticsearch already running"
else
	@echo "===> Starting elasticsearch"
	@docker rm -f elasticsearch || true
	@docker run --init -d --name elasticsearch -p 9200:9200 malice/elasticsearch:6.3; sleep 10
endif

.PHONY: gotest
gotest: check_env start_elasticsearch
	@echo "===> ${NAME} gotest"
	@MALICE_ELASTICSEARCH=localhost go run *.go -V --api ${MALICE_VT_API} lookup $(FOUND_HASH)

.PHONY: test
test: check_env
	@echo "===> ${NAME} --help"
	@docker run --rm $(ORG)/$(NAME):$(VERSION)
	@echo "===> Test lookup found"
	@docker run --rm $(ORG)/$(NAME):$(VERSION) -V --api ${MALICE_VT_API} lookup $(FOUND_HASH) | jq . > docs/results.json
	cat docs/results.json | jq .
	@echo "===> Test lookup NOT found"
	@docker run --rm $(ORG)/$(NAME):$(VERSION) -V --api ${MALICE_VT_API} lookup $(MISSING_HASH) | jq . > docs/no_results.json
	cat docs/no_results.json | jq .

.PHONY: test_elastic
test_elastic: start_elasticsearch
	@echo "===> ${NAME} test_elastic found"
	docker run --rm --link elasticsearch -e MALICE_ELASTICSEARCH=elasticsearch $(ORG)/$(NAME):$(VERSION) -V --api ${MALICE_VT_API} lookup $(FOUND_HASH)
	@echo "===> ${NAME} test_elastic NOT found"
	docker run --rm --link elasticsearch -e MALICE_ELASTICSEARCH=elasticsearch $(ORG)/$(NAME):$(VERSION) -V --api ${MALICE_VT_API} lookup $(MISSING_HASH)
	http localhost:9200/malice/_search | jq . > docs/elastic.json

.PHONY: test_markdown
test_markdown: test_elastic
	@echo "===> ${NAME} test_markdown"
	# http localhost:9200/malice/_search query:=@docs/query.json | jq . > docs/elastic.json
	cat docs/elastic.json | jq -r '.hits.hits[] ._source.plugins.${CATEGORY}.${NAME}.markdown' > docs/SAMPLE.md

.PHONY: circle
circle: ci-size
	@sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell cat .circleci/size)-blue/' README.md
	@echo "===> Image size is: $(shell cat .circleci/size)"

ci-build:
	@echo "===> Getting CircleCI build number"
	@http https://circleci.com/api/v1.1/project/github/${REPO} | jq '.[0].build_num' > .circleci/build_num

ci-size: ci-build
	@echo "===> Getting artifact sizes from CircleCI"
	@cd .circleci; rm size nsrl bloom || true
	@http https://circleci.com/api/v1.1/project/github/${REPO}/$(shell cat .circleci/build_num)/artifacts${CIRCLE_TOKEN} | jq -r ".[] | .url" | xargs wget -q -P .circleci

clean:
	docker-clean stop
	docker rmi $(ORG)/$(NAME):$(VERSION)


# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := all
