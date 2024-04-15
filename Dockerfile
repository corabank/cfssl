FROM --platform=${TARGETPLATFORM} img.cora.tools/dockerhub/library/golang:1.22

ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN echo "I am running on $BUILDPLATFORM, building for $TARGETPLATFORM" 

LABEL org.opencontainers.image.source https://github.com/cloudflare/cfssl
LABEL org.opencontainers.image.description "Cloudflare's PKI toolkit"

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workdir
COPY . /workdir

RUN git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl && \
    make clean && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} make all && cp bin/* /usr/bin/

RUN go install bitbucket.org/liamstask/goose/cmd/goose@latest

EXPOSE 8888

ENTRYPOINT ["cfssl"]
CMD ["--help"]
