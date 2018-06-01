FROM golang:1.8.5-alpine as builder
ARG GOPROXY_VERSION=master
RUN apk update && apk upgrade && \
    apk add --no-cache git && cd /go/src/ && git clone https://github.com/lanimei/Proxylanimei && \
	cd Proxylanimei && git checkout ${GOPROXY_VERSION} && \
    go get && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o proxy
FROM alpine:3.7
COPY --from=builder /go/src/Proxylanimei/proxy /
COPY ./proxy.crt /
COPY ./proxy.key /
CMD /proxy server -r ":28080@:22" -P "172.16.19.102:33080" -C proxy.crt -K proxy.key

