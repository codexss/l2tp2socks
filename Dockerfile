FROM golang:1.26.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/govpn/go.mod third_party/govpn/go.sum ./third_party/govpn/
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/l2tp2socks ./cmd/l2tp2socks

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/l2tp2socks /l2tp2socks
USER 65532:65532
ENTRYPOINT ["/l2tp2socks"]
CMD ["-config", "/config/config.json"]
