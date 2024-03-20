FROM fedora:latest

RUN dnf update -y && \
    dnf install -y \
    gcc \
    gcc-c++ \
    kernel-devel \
    make \
    automake \
    pkg-config \
    fuse3-devel \
    poco-devel \
    boost-devel && \
    dnf clean all

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
