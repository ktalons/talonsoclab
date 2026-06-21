# ---- build stage: grab the ProjectDiscovery binaries ----
# Base image pinned for reproducibility. Tool versions are build args: they default
# to @latest so a fresh build always works, but pin them (e.g. v2.6.6) the moment
# your stack is stable — pass --build-arg SUBFINDER_VERSION=v2.6.6 etc.
FROM golang:1.23-alpine AS build
ARG SUBFINDER_VERSION=latest
ARG HTTPX_VERSION=latest
ARG NUCLEI_VERSION=latest
RUN apk add --no-cache git build-base
ENV CGO_ENABLED=0
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
 && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}

# ---- runtime stage: slim image, no Go toolchain ----
FROM alpine:3.20
RUN apk add --no-cache python3 jq ca-certificates bind-tools \
 && adduser -D -u 10001 recon
COPY --from=build /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=build /go/bin/httpx    /usr/local/bin/httpx
COPY --from=build /go/bin/nuclei   /usr/local/bin/nuclei
COPY run-recon.sh /opt/recon/run-recon.sh
COPY diff.py      /opt/recon/diff.py
RUN chmod +x /opt/recon/run-recon.sh
USER recon
# nuclei templates download to ~/.config on first run — persist via the recon_config volume.
ENTRYPOINT ["/opt/recon/run-recon.sh"]
