FROM ubuntu:focal

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
&& apt-get install -y libdb++-dev build-essential python3-dev python3-pip python3-click python3-arrow python3-base58 python3-bsddb3 python3-protobuf git wget tini

RUN pip3 install walletlib==0.2.10
WORKDIR /app
ENTRYPOINT ["tini", "--", "dumpwallet"]
CMD ["--help"]
