FROM ubuntu:rolling

RUN apt-get update && \
    apt-get -y --no-install-recommends install \
        build-essential \
        automake \
        libfuse-dev \
        librlog-dev \
        libpoco-dev \
        libboost-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
