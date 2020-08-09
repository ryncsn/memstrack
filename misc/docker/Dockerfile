ARG BASE_IMAGE

FROM ${BASE_IMAGE:-ubuntu}

RUN apt update && apt install gcc make libncurses-dev && apt clean

WORKDIR /mnt
