FROM rust:1.85-slim AS build
WORKDIR /src
COPY . .
RUN cargo test --locked || cargo test
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -r -u 65532 berry
COPY --from=build /src/target/release/berryshield-risk-engine /usr/local/bin/berryshield-risk-engine
USER 65532:65532
EXPOSE 8082
ENTRYPOINT ["/usr/local/bin/berryshield-risk-engine"]
