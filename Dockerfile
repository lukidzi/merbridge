
FROM ubuntu:22.04 as compiler

WORKDIR /app

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y git make flex libelf-dev clang libcap-dev libbfd-dev \
      pkg-config

ARG LLVM_STRIP=llvm-strip-14

ADD . .

# Step to cache it when building docker image
RUN make \
  LLVM_STRIP=$LLVM_STRIP \
  --directory /app/bpf \
  /app/bpf/.output/bpftool \
  /app/bpf/.output/bpftool/bootstrap/bpftool \
  /app/bpf/.output/libbpf.a

ARG DEBUG=0

RUN make \
  MESH_MODE=kuma \
  DEBUG=$DEBUG \
  USE_RECONNECT=1 \
  LLVM_STRIP=$LLVM_STRIP \
  --directory /app/bpf \
  all

RUN rm -rf /app/bpf/mb_*.*

FROM golang:1.19.2 as mbctl

WORKDIR /app

ADD go.mod .
ADD go.sum .

RUN go mod download

ADD . .

RUN go build -ldflags "-s -w" -o ./dist/mbctl ./app/main.go
RUN go build -ldflags "-s -w" -o ./dist/merbridge-cni ./app/cni/main.go
RUN go build -ldflags "-s -w" -o ./dist/merbridge-fd-back ./app/fd-back/main.go

FROM ubuntu:22.04

WORKDIR /app

RUN apt-get update && apt-get install -y libelf-dev make sudo clang iproute2 ethtool
COPY --from=compiler /app/bpf/.output/bpftool/bpftool /usr/local/sbin/bpftool
COPY --from=compiler /app/bpf/mb_* /app/bpf/
COPY --from=mbctl /app/dist/mbctl mbctl
COPY --from=mbctl /app/dist/merbridge-cni merbridge-cni
COPY --from=mbctl /app/dist/merbridge-fd-back merbridge-fd-back

CMD /app/mbctl
