FROM --platform=$BUILDPLATFORM ghcr.io/cybozu/golang:1.24-noble as dev

COPY ./main.go /src/
WORKDIR /src

RUN go mod init test.echo
RUN CGO_ENABLED=0 go build -o echotest .


FROM --platform=$TARGETPLATFORM wbitt/network-multitool:alpine-extra

# Add kube-vip binary
COPY --from=dev /src/echotest /
ENTRYPOINT ["/echotest"]
