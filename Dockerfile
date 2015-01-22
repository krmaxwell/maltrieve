#
# This Docker image encapsulates Maltrieve, a tool to retrieve malware
# directly from the source for security researchers.
# which was created by Kyle Maxwell (technoskald) and is
# available at https://github.com/technoskald/maltrieve.
#
# The file below is based on ideas from Spenser Reinhardt's Dockerfile
# (https://registry.hub.docker.com/u/sreinhardt/honeynet/dockerfile)
# and on instructions outlined by M. Fields (@shakey_1).
#
# To run this image after installing Docker, use a command like this:
#
# sudo docker run --rm -it technoskald/maltrieve bash
#
# then run ./maltrieve.py with the desired parameters.

FROM ubuntu:14.04
MAINTAINER Michael Boman <michael@michaelboman.org>

USER root
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    gcc \
    git \
    libpython2.7-stdlib \
    python2.7 \
    python2.7-dev \
    python-pip \
    python-setuptools && \

  rm -rf /var/lib/apt/lists/* && \

  groupadd -r maltrieve && \
  useradd -r -g maltrieve -d /home/maltrieve -s /sbin/nologin -c "Maltrieve User" maltrieve

WORKDIR /home
RUN git clone https://github.com/technoskald/maltrieve.git && \
  cd maltrieve && \
  pip install -r requirements.txt

USER maltrieve
ENV HOME /home/maltrieve
ENV USER maltrieve
WORKDIR /home/maltrieve
CMD ["./maltrieve.py"]

