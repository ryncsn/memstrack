ARG BASE_IMAGE

FROM ${BASE_IMAGE:-ubuntu}

RUN apt-get update && apt-get install -y gcc make sudo libncurses-dev && apt-get clean

WORKDIR /mnt
