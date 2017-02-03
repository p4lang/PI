FROM p4lang/behavioral-model:latest
MAINTAINER Antonin Bas <antonin@barefootnetworks.com>

# Default to using 2 make jobs, which is a good default for CI. If you're
# building locally or you know there are more cores available, you may want to
# override this.
ARG MAKEFLAGS
ENV MAKEFLAGS ${MAKEFLAGS:--j2}

ARG CXX
ENV CXX ${CXX:-g++}

ARG CC
ENV CC ${CC:-gcc}

ENV PI_DEPS automake \
            build-essential \
            g++ \
            clang-3.8 \
            clang-format-3.8 \
            libboost-dev \
            libboost-system-dev \
            libtool \
            pkg-config \
            python2.7 \
            libjudy-dev \
            libreadline-dev \
            libpcap-dev \
            libmicrohttpd-dev \
            doxygen \
            valgrind
COPY . /PI/
WORKDIR /PI/
RUN apt-get update && \
    apt-get install -y --no-install-recommends $PI_DEPS && \
    ./autogen.sh && \
    ./configure --with-bmv2 --with-proto && \
    make
