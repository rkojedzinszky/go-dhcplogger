FROM golang:alpine3.18 AS build

RUN apk --no-cache add gcc libc-dev libpcap-dev

ADD . /go/src/github.com/rkojedzinszky/go-dhcplogger

RUN cd /go/src/github.com/rkojedzinszky/go-dhcplogger && go build . && \
    strip -s go-dhcplogger

FROM alpine:3.18

LABEL org.opencontainers.image.authors "Richard Kojedzinszky <richard@kojedz.in>"
LABEL org.opencontainers.image.source https://github.com/rkojedzinszky/go-dhcplogger

COPY --from=build /go/src/github.com/rkojedzinszky/go-dhcplogger/go-dhcplogger /

RUN apk --no-cache add libpcap libcap && \
    setcap cap_net_raw+ep /go-dhcplogger && \
    apk del libcap

USER 65534

CMD ["/go-dhcplogger", "-interface=eth0"]
