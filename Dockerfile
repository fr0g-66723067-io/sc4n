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
# The labels are what a registry listing and a consumer's policy engine read, so
# the version a report carries and the version a tag claims are one value, passed
# from the same build argument.
ARG VERSION=dev
LABEL org.opencontainers.image.title="sc4n" \
      org.opencontainers.image.description="Static scanner for ML model artifacts and the code around them. Never executes the artifact." \
      org.opencontainers.image.source="https://github.com/fr0g-66723067-io/sc4n" \
      org.opencontainers.image.documentation="https://github.com/fr0g-66723067-io/sc4n/blob/main/docs/quickstart.md" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/sc4n /usr/local/bin/sc4n
USER 65532:65532
ENV TMPDIR=/tmp
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/sc4n"]
CMD ["scan", "-h"]
