FROM debian:unstable-slim

RUN apt-get update
RUN apt-get -y --no-install-recommends install \
    build-essential \
    automake \
    libfuse-dev \
    librlog-dev \
    libpoco-dev \
    libboost-dev

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
