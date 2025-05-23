FROM golang:1.24-alpine3.22 AS build-env

ARG TARGETARCH

COPY . /workdir
WORKDIR /workdir

RUN GOARCH=${TARGETARCH} CGO_ENABLED=0 GOOS=linux go build -o echotest main.go

FROM alpine:3.22

RUN apk add --update curl \
    && rm -rf /var/cache/apk/*

COPY --from=build-env /workdir/echotest /usr/local/bin/echotest
