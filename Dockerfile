FROM golang:1.25.13-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/bananauth ./cmd/server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/bananauth /usr/local/bin/bananauth
ENV LISTEN_ADDR=:3000
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/bananauth"]
