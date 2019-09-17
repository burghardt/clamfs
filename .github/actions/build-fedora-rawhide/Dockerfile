FROM fedora:rawhide

RUN dnf update -y
RUN dnf install -y \
    gcc \
    gcc-c++ \
    kernel-devel \
    automake \
    fuse-devel \
    commoncpp2-devel \
    rlog-devel \
    poco-devel \
    boost-devel

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
