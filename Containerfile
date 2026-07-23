FROM registry.access.redhat.com/ubi10/ubi@sha256:fb92193e9466fb59207a8e33caebaab23d1b4780c53e89127c1f425615f9e7ac

RUN dnf --assumeyes \
        --setopt=install_weak_deps=False \
        install python3 python3-pyyaml \
    && dnf clean all \
    && ln -s /usr/bin/python3 /usr/local/bin/python \
    && mkdir /workspace
