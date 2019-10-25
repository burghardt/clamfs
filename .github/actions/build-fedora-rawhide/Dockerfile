FROM fedora:rawhide

RUN dnf update -y && \
    dnf install -y \
    gcc \
    gcc-c++ \
    kernel-devel \
    make \
    automake \
    pkg-config \
    fuse3-devel \
    rlog-devel \
    poco-devel \
    boost-devel

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
