# Build context is the parent workspace containing both repositories:
#   cliptown-rust-backend.rs/
#   cliptown-interfaces/
FROM rust:1.88-bookworm AS build
WORKDIR /workspace
COPY cliptown-interfaces /workspace/cliptown-interfaces
COPY cliptown-rust-backend.rs /workspace/cliptown-rust-backend.rs
WORKDIR /workspace/cliptown-rust-backend.rs
RUN cargo build --locked --release --bin cliptown-api

FROM gcr.io/distroless/cc-debian12:nonroot
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/cliptown/cliptown-rust-backend.rs" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.title="ClipTown API"
COPY --from=build /workspace/cliptown-rust-backend.rs/target/release/cliptown-api /usr/local/bin/cliptown-api
EXPOSE 3000
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cliptown-api"]
