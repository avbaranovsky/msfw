FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
	build-essential \
	cmake \
	linux-tools-common \
	linux-tools-generic \
	&& rm -rf /var/lib/apt/lists

RUN ln -s /usr/lib/linux-tools/*/perf /usr/bin/perf || true

WORKDIR /app

COPY . .

RUN mkdir build && cd build && cmake .. && make

CMD ["./build/msfw"]
