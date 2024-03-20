FROM debian:unstable-slim

RUN apt-get update && \
    apt-get -y --no-install-recommends install \
        build-essential \
        automake \
        pkg-config \
        libfuse3-dev \
        libpoco-dev \
        libboost-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
