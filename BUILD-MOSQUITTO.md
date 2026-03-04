# Build Mosquitto From Source (When `2.1.3-alpine` Is Delayed)

If the official `eclipse-mosquitto:2.1.3-alpine` image takes too long to appear,
you can build Mosquitto yourself and still run the Rust auth plugin.

## 1) Create a custom Dockerfile

Create `mqtt-auth-biscuit/docker/Dockerfile.mosquitto.custom`:

```dockerfile
# Stage 1: build Rust plugin (.so)
FROM rust:1.93.1-alpine AS plugin-builder
RUN apk add --no-cache build-base cmake perl libc-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/mosquitto-plugin ./crates/mosquitto-plugin
COPY crates/token-issuer ./crates/token-issuer
COPY crates/benchmarks ./crates/benchmarks
COPY crates/authz-server ./crates/authz-server
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release -p mosquitto-auth-biscuit

# Stage 2: build Mosquitto from source
FROM alpine:3.23.3 AS mosq-builder
ARG MOSQ_REF=v2.1.3
RUN apk add --no-cache git build-base cmake openssl-dev cjson-dev libwebsockets-dev c-ares-dev
RUN git clone https://github.com/eclipse-mosquitto/mosquitto.git /src
WORKDIR /src
RUN git checkout ${MOSQ_REF}
RUN make -j"$(nproc)" prefix=/usr WITH_SHARED_LIBRARIES=yes
RUN make install DESTDIR=/out

# Stage 3: runtime
FROM alpine:3.23.3
RUN apk add --no-cache ca-certificates libstdc++ openssl cjson libwebsockets c-ares
COPY --from=mosq-builder /out/ /
COPY --from=plugin-builder /app/target/release/libmosquitto_auth_biscuit.so /mosquitto/plugins/
COPY docker/jwt_public.pem /mosquitto/config/
COPY docker/biscuit_public.key /mosquitto/config/
CMD ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
```

## 2) Build the image

From `mqtt-auth-biscuit/docker`:

```bash
docker build -f Dockerfile.mosquitto.custom -t mosquitto:2.1.3-custom ..
```

If `v2.1.3` is not tagged yet, use a commit SHA that contains your feature:

```bash
docker build -f Dockerfile.mosquitto.custom \
  --build-arg MOSQ_REF=<commit-sha> \
  -t mosquitto:2.1.3-custom ..
```

## 3) Use it in Compose

In `mqtt-auth-biscuit/docker/docker-compose.yml`, for the `mosquitto` service,
replace `build:` with:

```yaml
image: mosquitto:2.1.3-custom
```

(or keep a `build:` section that points to `Dockerfile.mosquitto.custom`).

## 4) Verify version inside container

```bash
docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml run --rm mosquitto mosquitto -h | head -n 1
```

## Notes

- Prefer a commit SHA over a moving branch for reproducibility.
- Keep the image tag explicit (`2.1.3-custom`, `2.1.3-rc`, etc.) to avoid confusion.
- Once `eclipse-mosquitto:2.1.3-alpine` is published, you can switch back to the official image.
