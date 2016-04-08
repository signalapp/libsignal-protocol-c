FROM ubuntu
MAINTAINER Stewart Henderson <stewart.henderson@protonmail.com>

RUN apt-get -y install software-properties-common
RUN add-apt-repository ppa:ubuntu-toolchain-r/test 
RUN apt-get update
RUN apt-get -y install gcc-4.9 g++-4.9 cmake build-essential


RUN mkdir /development
RUN mkdir /development/build
ADD . /development
RUN cd /development/build \
	&& cmake -DCMAKE_BUILD_TYPE=Debug .. \
	&& make
