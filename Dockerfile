FROM golang:1.16 as golayer

RUN apt-get update -y && apt-get install -y ca-certificates

ADD go.mod /go/src/github.com/dvaldivia/reverse-proxy/go.mod
ADD go.sum /go/src/github.com/dvaldivia/reverse-proxy/go.sum
WORKDIR /go/src/github.com/dvaldivia/reverse-proxy/

# Get dependencies - will also be cached if we won't change mod/sum
RUN go mod download

ADD . /go/src/github.com/dvaldivia/reverse-proxy/
WORKDIR /go/src/github.com/dvaldivia/reverse-proxy/

ENV CGO_ENABLED=0

RUN go build -trimpath -ldflags "-w -s" -a -o reverse-proxy .

FROM ubuntu

MAINTAINER MinIO Development "dev@min.io"

EXPOSE 8443

RUN apt update && apt install -y curl

COPY --from=golayer /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=golayer /go/src/github.com/dvaldivia/reverse-proxy/reverse-proxy .

ENTRYPOINT ["/reverse-proxy"]
