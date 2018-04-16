.PHONY: all docs-verify docs docs-clean docs-build

PROXY_BUILD_ARGS := $(if $(HTTP_PROXY), --build-arg "HTTP_PROXY=$(HTTP_PROXY)",) $(if $(HTTPS_PROXY), --build-arg "HTTPS_PROXY=$(HTTPS_PROXY)",) $(if $(NO_PROXY), --build-arg "NO_PROXY=$(NO_PROXY)",) $(if $(http_proxy), --build-arg "http_proxy=$(http_proxy)",) $(if $(https_proxy), --build-arg "https_proxy=$(https_proxy)",) $(if $(no_proxy), --build-arg "no_proxy=$(no_proxy)",) 
NPM_BUILD_ARGS := $(if $(npm_config_registry), --build-arg "npm_config_registry=$(npm_config_registry)",) $(if $(yarn_config_registry), --build-arg "yarn_config_registry=$(yarn_config_registry)",)
PROXY_ENVS := $(if $(HTTP_PROXY), -e "HTTP_PROXY=$(HTTP_PROXY)",) $(if $(HTTPS_PROXY), -e "HTTPS_PROXY=$(HTTPS_PROXY)",) $(if $(NO_PROXY), -e "NO_PROXY=$(NO_PROXY)",) $(if $(http_proxy), -e "http_proxy=$(http_proxy)",) $(if $(https_proxy), -e "https_proxy=$(https_proxy)",) $(if $(no_proxy), -e "no_proxy=$(no_proxy)",) 

TRAEFIK_ENVS := \
	-e OS_ARCH_ARG \
	-e OS_PLATFORM_ARG \
	-e TESTFLAGS \
	-e VERBOSE \
	-e VERSION \
	-e CODENAME \
	-e TESTDIRS \
	-e CI \
	-e CONTAINER=DOCKER		# Indicator for integration tests that we are running inside a container.

SRCS = $(shell git ls-files '*.go' | grep -v '^vendor/')

BIND_DIR := dist
TRAEFIK_MOUNT := -v "$(CURDIR)/$(BIND_DIR):/go/src/github.com/containous/traefik/$(BIND_DIR):z"

GIT_BRANCH := $(subst heads/,,$(shell git rev-parse --abbrev-ref HEAD 2>/dev/null))
TRAEFIK_DEV_IMAGE := traefik-dev$(if $(GIT_BRANCH),:$(subst /,-,$(GIT_BRANCH)))
REPONAME := $(shell echo $(REPO) | tr '[:upper:]' '[:lower:]')
TRAEFIK_IMAGE := $(if $(REPONAME),$(REPONAME),"containous/traefik")
INTEGRATION_OPTS := $(if $(MAKE_DOCKER_HOST),-e "DOCKER_HOST=$(MAKE_DOCKER_HOST)", -e "TEST_CONTAINER=1" -v "/var/run/docker.sock:/var/run/docker.sock")
TRAEFIK_DOC_IMAGE := traefik-docs
TRAEFIK_DOC_VERIFY_IMAGE := $(TRAEFIK_DOC_IMAGE)-verify

DOCKER_BUILD_ARGS := $(if $(DOCKER_VERSION), --build-arg "DOCKER_VERSION=$(DOCKER_VERSION)",)
DOCKER_RUN_OPTS := $(TRAEFIK_ENVS) $(TRAEFIK_MOUNT) "$(TRAEFIK_DEV_IMAGE)"
DOCKER_CMD := docker
DOCKER_RUN_TRAEFIK := $(DOCKER_CMD) run $(PROXY_ENVS) $(INTEGRATION_OPTS) $(DOCKER_RUN_OPTS)  
DOCKER_RUN_TRAEFIK_NOTTY := $(DOCKER_CMD) run $(PROXY_ENVS) $(INTEGRATION_OPTS) $(DOCKER_RUN_OPTS) 
DOCKER_RUN_DOC_PORT := 8000
DOCKER_RUN_DOC_MOUNT := -v $(CURDIR):/mkdocs
DOCKER_RUN_DOC_OPTS := --rm $(DOCKER_RUN_DOC_MOUNT) -p $(DOCKER_RUN_DOC_PORT):8000

print-%: ; @echo $*=$($*)

default: binary

all: generate-webui build ## validate all checks, build linux binary, run all tests\ncross non-linux binaries
	$(DOCKER_RUN_TRAEFIK) /bin/bash ./script/make.sh

binary: generate-webui build ## build the linux binary
	$(DOCKER_RUN_TRAEFIK) /bin/bash ./script/make.sh generate binary

crossbinary: generate-webui build ## cross build the non-linux binaries
	$(DOCKER_RUN_TRAEFIK) /bin/bash ./script/make.sh generate crossbinary

crossbinary-parallel:
	$(MAKE) generate-webui
	$(MAKE) build crossbinary-default crossbinary-others

crossbinary-default: generate-webui build
	$(DOCKER_RUN_TRAEFIK_NOTTY) /bin/bash ./script/make.sh generate crossbinary-default

crossbinary-default-parallel:
	$(MAKE) generate-webui
	$(MAKE) build crossbinary-default

crossbinary-others: generate-webui build
	$(DOCKER_RUN_TRAEFIK_NOTTY) /bin/bash ./script/make.sh generate crossbinary-others

crossbinary-others-parallel:
	$(MAKE) generate-webui
	$(MAKE) build crossbinary-others

test: build ## run the unit and integration tests
	$(DOCKER_RUN_TRAEFIK) /bin/bash ./script/make.sh generate test-unit binary test-integration

test-unit: build ## run the unit tests
	$(DOCKER_RUN_TRAEFIK) /bin/bash ./script/make.sh generate test-unit

test-integration: build ## run the integration tests
	$(DOCKER_RUN_TRAEFIK) /bin/bash ./script/make.sh generate binary test-integration
	TEST_HOST=1 /bin/bash ./script/make.sh test-integration

validate: build  ## validate code, vendor and autogen
	$(DOCKER_RUN_TRAEFIK) /bin/bash ./script/make.sh validate-gofmt validate-govet validate-golint validate-misspell validate-vendor validate-autogen

build: dist
	$(DOCKER_CMD) build $(PROXY_BUILD_ARGS) $(DOCKER_BUILD_ARGS) -t "$(TRAEFIK_DEV_IMAGE)" -f build.Dockerfile .

build-webui:
	$(DOCKER_CMD) build $(PROXY_BUILD_ARGS) $(NPM_BUILD_ARGS) -t traefik-webui -f webui/Dockerfile webui

build-no-cache: dist
	$(DOCKER_CMD) build --no-cache $(PROXY_BUILD_ARGS) -t "$(TRAEFIK_DEV_IMAGE)" -f build.Dockerfile .

shell: build ## start a shell inside the build env
	$(DOCKER_RUN_TRAEFIK) /bin/bash

image-dirty: binary ## build a docker traefik image
	$(DOCKER_CMD) build $(PROXY_BUILD_ARGS) -t $(TRAEFIK_IMAGE) .

image: clear-static binary ## clean up static directory and build a docker traefik image
	$(DOCKER_CMD) build $(PROXY_BUILD_ARGS) -t $(TRAEFIK_IMAGE) .

docs-image:
	docker build -t $(TRAEFIK_DOC_IMAGE) -f docs.Dockerfile .

docs: docs-image
	$(DOCKER_CMD) run  $(DOCKER_RUN_DOC_OPTS) $(TRAEFIK_DOC_IMAGE) mkdocs serve

docs-image:
	$(DOCKER_CMD) build $(PROXY_BUILD_ARGS) -t $(TRAEFIK_DOC_IMAGE) -f docs.Dockerfile .
docs-build: site

docs-verify: site
	docker build -t $(TRAEFIK_DOC_VERIFY_IMAGE) ./script/docs-verify-docker-image ## Build Validator image
	docker run --rm -v $(CURDIR):/app $(TRAEFIK_DOC_VERIFY_IMAGE) ## Check for dead links and w3c compliance

site: docs-image
	docker run  $(DOCKER_RUN_DOC_OPTS) $(TRAEFIK_DOC_IMAGE) mkdocs build

docs-clean:
	rm -rf $(CURDIR)/site

clear-static:
	rm -rf static || true #Sometimes only user in container has permissions

dist:
	mkdir dist

run-dev:
	go generate
	go build ./cmd/traefik
	./traefik

generate-webui: build-webui
	mkdir -p static; \
	$(DOCKER_CMD) run --rm -v "$(CURDIR)/static:/src/static:z" traefik-webui /bin/bash -c "rm -rf /src/static || true && npm run build"; \
	echo 'For more informations show `webui/readme.md`' > $(CURDIR)/static/DONT-EDIT-FILES-IN-THIS-DIRECTORY.md; \

lint:
	script/validate-golint

fmt:
	gofmt -s -l -w $(SRCS)

pull-images:
	grep --no-filename -E '^\s+image:' ./integration/resources/compose/*.yml | awk '{print $$2}' | sort | uniq  | xargs -P 6 -n 1 $(DOCKER_CMD) pull

dep-ensure:
	dep ensure -v
	/bin/bash ./script/prune-dep.sh

dep-prune:
	/bin/bash ./script/prune-dep.sh

help: ## this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
