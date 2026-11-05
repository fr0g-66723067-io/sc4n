# The release image. It exists because a path check bounds what the scanner
# *resolves*, not what it may read: the container's filesystem view is the only
# control that covers a hardlink to an outside file, a spill write or an
# accidental device node. Run it with --network=none --read-only for a scan.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/sc4n ./cmd/sc4n

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sc4n /usr/local/bin/sc4n
USER 65532:65532
ENV TMPDIR=/tmp
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/sc4n"]
CMD ["scan", "-h"]
