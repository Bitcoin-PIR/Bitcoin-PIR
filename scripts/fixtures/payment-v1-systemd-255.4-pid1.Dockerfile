FROM ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
ARG SYSTEMD_VERSION=255.4-1ubuntu8.15
ARG UBUNTU_SNAPSHOT=20260414T120000Z
ARG SYSTEMD_AMD64_SHA256=eeee59d4b6a091c69d1e369b0570911d54b6625cf71d8bec750d3571645e7a44
ARG LIBSYSTEMD0_AMD64_SHA256=22cd1e9d9cd58bf8cdf41b2d85fed8a854e0888569f3bf9a3b5f86eee9e4208c
ARG LIBSYSTEMD_SHARED_AMD64_SHA256=a4d9127ea70c1008b49e69852bf6dcf745aeb039f6885f9671a0c752624c8c26
ARG SYSTEMD_ARM64_SHA256=5ee48f183162a417f560a98d122e90e5e3b2b7e040c7b71bd1b2d8d11b528513
ARG LIBSYSTEMD0_ARM64_SHA256=88dec2e5cc262c836748a944da05718d7026db39dd2871e577d6001306c62e02
ARG LIBSYSTEMD_SHARED_ARM64_SHA256=c212d51cd9a06edf7d2f0ad70453f90babf2c4443e7eade9e9826f5cbe143e4a
ARG SYSTEMD_DEV_SHA256=f9ef5f44bbbf718ba941e646e00e366609e8535367f176089376a5ad5852ff81

# The base image has no CA bundle. The first snapshot update therefore relies
# on Ubuntu archive signatures and package hashes while TLS verification is
# temporarily unavailable. ca-certificates is installed from that same pinned
# snapshot before any test executes.
RUN sed -E -i \
      "s#http://(archive.ubuntu.com/ubuntu|security.ubuntu.com/ubuntu|ports.ubuntu.com/ubuntu-ports)/#https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/#g" \
      /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update \
      -o Acquire::Check-Valid-Until=false \
      -o Acquire::https::Verify-Peer=false \
      -o Acquire::https::Verify-Host=false \
      -qq \
    && apt-get install -y -qq --no-install-recommends \
      -o Acquire::https::Verify-Peer=false \
      -o Acquire::https::Verify-Host=false \
      ca-certificates \
    && update-ca-certificates \
    && apt-get install -y -qq --no-install-recommends \
      curl \
      dbus \
      nodejs \
      passwd \
    && case "${TARGETARCH}" in \
      amd64) \
        package_arch=amd64; \
        systemd_sha256="${SYSTEMD_AMD64_SHA256}"; \
        libsystemd0_sha256="${LIBSYSTEMD0_AMD64_SHA256}"; \
        libsystemd_shared_sha256="${LIBSYSTEMD_SHARED_AMD64_SHA256}" \
        ;; \
      arm64) \
        package_arch=arm64; \
        systemd_sha256="${SYSTEMD_ARM64_SHA256}"; \
        libsystemd0_sha256="${LIBSYSTEMD0_ARM64_SHA256}"; \
        libsystemd_shared_sha256="${LIBSYSTEMD_SHARED_ARM64_SHA256}" \
        ;; \
      *) echo "unsupported native architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && test "$(dpkg --print-architecture)" = "${package_arch}" \
    && package_base="https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/pool/main/s/systemd" \
    && curl -fsSLo /tmp/systemd.deb \
      "${package_base}/systemd_${SYSTEMD_VERSION}_${package_arch}.deb" \
    && curl -fsSLo /tmp/libsystemd0.deb \
      "${package_base}/libsystemd0_${SYSTEMD_VERSION}_${package_arch}.deb" \
    && curl -fsSLo /tmp/libsystemd-shared.deb \
      "${package_base}/libsystemd-shared_${SYSTEMD_VERSION}_${package_arch}.deb" \
    && curl -fsSLo /tmp/systemd-dev.deb \
      "${package_base}/systemd-dev_${SYSTEMD_VERSION}_all.deb" \
    && printf '%s  %s\n' \
      "${systemd_sha256}" /tmp/systemd.deb \
      "${libsystemd0_sha256}" /tmp/libsystemd0.deb \
      "${libsystemd_shared_sha256}" /tmp/libsystemd-shared.deb \
      "${SYSTEMD_DEV_SHA256}" /tmp/systemd-dev.deb \
      | sha256sum --check --strict - \
    && apt-get install -y -qq --allow-downgrades --no-install-recommends \
      /tmp/libsystemd0.deb \
      /tmp/libsystemd-shared.deb \
      /tmp/systemd-dev.deb \
      /tmp/systemd.deb \
    && test "$(systemctl --version | sed -n '1p')" = \
      "systemd 255 (${SYSTEMD_VERSION})" \
    && test "$(dpkg-query -W -f='${Version}' systemd)" = "${SYSTEMD_VERSION}" \
    && test -x /usr/lib/systemd/systemd \
    && apt-get clean \
    && rm -f /tmp/systemd.deb /tmp/libsystemd0.deb \
      /tmp/libsystemd-shared.deb /tmp/systemd-dev.deb \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
ENV container=docker
CMD ["/usr/lib/systemd/systemd"]
