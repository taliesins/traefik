FROM golang:1.10-alpine

# Which docker version to test on
ARG DOCKER_VERSION=17.03.2
ARG DEP_VERSION=0.4.1

WORKDIR /go/src/github.com/containous/traefik
COPY . /go/src/github.com/containous/traefik

RUN apk --update upgrade \
&& apk --no-cache --no-progress add git mercurial bash gcc musl-dev curl tar \
&& rm -rf /var/cache/apk/* \
&& go get github.com/containous/go-bindata/... \
&& go get github.com/golang/lint/golint \
&& go get github.com/kisielk/errcheck \
&& go get github.com/client9/misspell/cmd/misspell \
&& mkdir -p /usr/local/bin \
&& curl -fsSL -o /usr/local/bin/dep https://github.com/golang/dep/releases/download/v${DEP_VERSION}/dep-linux-amd64 \
&& chmod +x /usr/local/bin/dep \
&& curl -fL https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}-ce.tgz | tar -xzC /usr/local/bin --transform 's#^.+/##x'
