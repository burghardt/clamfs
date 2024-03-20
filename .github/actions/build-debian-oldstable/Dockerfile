FROM debian:oldstable-slim

RUN apt-get update && \
    apt-get -y --no-install-recommends install \
        build-essential \
        automake \
        git ca-certificates meson ninja-build udev \
        pkg-config \
        libfuse-dev \
        libpoco-dev \
        libboost-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /tmp/fuse3 && \
    cd /tmp/fuse3 && \
    git clone --depth 1 https://github.com/libfuse/libfuse.git . && \
    mkdir build && \
    cd build && \
    meson .. && \
    ninja && \
    ninja install && \
    cd /tmp && \
    rm -fr fuse3

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
