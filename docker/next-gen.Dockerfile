# Multi-stage image for AdGuard Home Next-Gen.
# Produces linux/amd64 and linux/arm64 images via buildx.
#
# Frontend is built first and placed under build/static so go:embed picks it up.
#
# Local example:
#   docker buildx build -f docker/next-gen.Dockerfile \
#     --build-arg VERSION=dev --build-arg CHANNEL=development \
#     -t adguardhome-next-gen:local --load .

ARG GO_VERSION=1.27.3
ARG NODE_VERSION=24

FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm AS js-builder
WORKDIR /src
COPY client_v2/package.json client_v2/package-lock.json ./client_v2/
RUN --mount=type=cache,target=/root/.npm \
	npm --prefix client_v2 ci
COPY client_v2 ./client_v2
# client_v2 build-prod emits ../build/static relative to client_v2/
RUN npm --prefix client_v2 run build-prod

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS go-builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=v0.0.0
ARG CHANNEL=development
ARG SOURCE_DATE_EPOCH=0
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download
COPY . .
COPY --from=js-builder /src/build ./build
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	set -euo pipefail; \
	mkdir -p /out; \
	# Prefer explicit SOURCE_DATE_EPOCH from CI; fall back to now if unset/0.
	if [ "${SOURCE_DATE_EPOCH}" = "0" ] || [ -z "${SOURCE_DATE_EPOCH}" ]; then \
		SOURCE_DATE_EPOCH="$(date -u +%s)"; \
	fi; \
	export SOURCE_DATE_EPOCH; \
	CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
		CHANNEL="${CHANNEL}" VERSION="${VERSION}" \
		SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
		OUT=/out/AdGuardHome \
		sh ./scripts/make/go-build.sh; \
	chmod +x /out/AdGuardHome

FROM alpine:3.23 AS runtime
ARG BUILD_DATE=unknown
ARG VERSION=v0.0.0
ARG VCS_REF=unknown

LABEL \
	maintainer="AdGuard Home Next-Gen" \
	org.opencontainers.image.authors="AdGuard Home Next-Gen contributors" \
	org.opencontainers.image.created=$BUILD_DATE \
	org.opencontainers.image.description="Memory-efficient AdGuard Home fork for routers, OpenSticks, and SBCs" \
	org.opencontainers.image.documentation="https://github.com/LaurensBosscher/AdGuardHome-Next-Gen" \
	org.opencontainers.image.licenses="GPL-3.0" \
	org.opencontainers.image.revision=$VCS_REF \
	org.opencontainers.image.source="https://github.com/LaurensBosscher/AdGuardHome-Next-Gen" \
	org.opencontainers.image.title="AdGuard Home Next-Gen" \
	org.opencontainers.image.url="https://github.com/LaurensBosscher/AdGuardHome-Next-Gen" \
	org.opencontainers.image.vendor="AdGuard Home Next-Gen" \
	org.opencontainers.image.version=$VERSION

RUN apk --no-cache add ca-certificates libcap tzdata \
	&& mkdir -p /opt/adguardhome/conf /opt/adguardhome/work \
	&& chown -R nobody:nogroup /opt/adguardhome

COPY --from=go-builder --chmod=0755 --chown=nobody:nogroup /out/AdGuardHome /opt/adguardhome/AdGuardHome

RUN setcap 'cap_net_bind_service=+eip' /opt/adguardhome/AdGuardHome

# 53     : TCP, UDP : DNS
# 67     :      UDP : DHCP (server)
# 68     :      UDP : DHCP (client)
# 80     : TCP      : HTTP (main)
# 443    : TCP, UDP : HTTPS, DNS-over-HTTPS (incl. HTTP/3), DNSCrypt (main)
# 853    : TCP, UDP : DNS-over-TLS, DNS-over-QUIC
# 3000   : TCP, UDP : HTTP(S) (alt, incl. HTTP/3)
# 5443   : TCP, UDP : DNSCrypt (alt)
# 6060   : TCP      : HTTP (pprof)
EXPOSE 53/tcp 53/udp \
	67/udp \
	68/udp \
	80/tcp \
	443/tcp 443/udp \
	853/tcp 853/udp \
	3000/tcp 3000/udp \
	5443/tcp 5443/udp \
	6060/tcp

WORKDIR /opt/adguardhome/work

ENTRYPOINT ["/opt/adguardhome/AdGuardHome"]

CMD [ \
	"--no-check-update", \
	"-c", "/opt/adguardhome/conf/AdGuardHome.yaml", \
	"-w", "/opt/adguardhome/work" \
]
