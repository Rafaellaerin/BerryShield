FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/berryshield-gateway .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/berryshield-gateway /berryshield-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/berryshield-gateway"]
