# Copyright 2017 Barefoot Networks, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Antonin Bas (antonin@barefootnetworks.com)

FROM p4lang/third-party:latest
LABEL maintainer="P4 Developers <p4-dev@lists.p4.org>"
LABEL description="This Docker image includes only the most widely-used PI \
artifacts: PI core and P4Runtime. It does not include the Thrift-based PI \
implementation for the bmv2 backend."

# Default to using 2 make jobs, which is a good default for CI. If you're
# building locally or you know there are more cores available, you may want to
# override this.
ARG MAKEFLAGS=-j2

# Select the type of image we're building. Use `build` for a normal build, which
# is optimized for image size. Use `test` if this image will be used for
# testing; in this case, the source code and build-only dependencies will not be
# removed from the image.
ARG IMAGE_TYPE=build

ENV PI_DEPS automake \
            build-essential \
            g++ \
            libboost-dev \
            libboost-system-dev \
            libboost-thread-dev \
            libtool \
            pkg-config
ENV PI_RUNTIME_DEPS libboost-system1.71.0 \
                    libboost-thread1.71.0 \
                    python3 \
                    python-is-python3

COPY . /PI/
WORKDIR /PI/
RUN apt-get update && \
    apt-get install -y --no-install-recommends $PI_DEPS $PI_RUNTIME_DEPS && \
    ./autogen.sh && \
    ./configure --enable-Werror --without-bmv2 --without-internal-rpc --without-cli --with-proto --with-sysrepo && \
    make && \
    make install-strip && \
    (test "$IMAGE_TYPE" = "build" && \
      apt-get purge -y $PI_DEPS && \
      apt-get autoremove --purge -y && \
      rm -rf /PI /var/cache/apt/* /var/lib/apt/lists/* && \
      echo 'Build image ready') || \
    (test "$IMAGE_TYPE" = "test" && \
      echo 'Test image ready')
