# Build Mosquitto From Source (When `2.1.3-alpine` Is Delayed)

If the official `eclipse-mosquitto:2.1.3-alpine` image takes too long to appear,
you can build Mosquitto yourself and still run the Rust auth plugin.

This migration requires Mosquitto commit `43c271504277941a4423a7e8c6b07bbcb611080b`
or newer so `MOSQ_EVT_BASIC_AUTH` exposes `password_len` for binary `CONNECT`
passwords.

Older brokers are unsupported with the current plugin. The auth path now
assumes the newer `MOSQ_EVT_BASIC_AUTH` layout at runtime, so using an older
broker may fail later as confusing `CONNECT` authentication errors rather than
as a clean startup error.

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
RUN RUSTFLAGS="-C target-feature=-crt-static -C strip=symbols" cargo build --release -p mosquitto-auth-biscuit
RUN strip --strip-unneeded /app/target/release/libmosquitto_auth_biscuit.so

# Stage 2: build Mosquitto from source
FROM alpine:3.23.3 AS mosq-builder
ARG MOSQ_REF=b3b4d77ef3faef6dfcdfac3fb00a9b5a42859aca
RUN apk add --no-cache git build-base cmake openssl-dev cjson-dev libwebsockets-dev c-ares-dev
RUN git clone https://github.com/eclipse-mosquitto/mosquitto.git /src
WORKDIR /src
RUN git checkout ${MOSQ_REF}
RUN make -j"$(nproc)" prefix=/usr WITH_SHARED_LIBRARIES=yes WITH_DOCS=no WITH_EDITLINE=no WITH_HTTP_API=no WITH_SQLITE=no
RUN make prefix=/usr WITH_SHARED_LIBRARIES=yes WITH_DOCS=no WITH_EDITLINE=no WITH_HTTP_API=no WITH_SQLITE=no install DESTDIR=/out
RUN set -eux; \
    for f in /out/usr/sbin/mosquitto /out/usr/lib/libmosquitto.so.1 /out/usr/lib/libmosquitto_common.so.1 /out/usr/lib/mosquitto_*.so /out/usr/bin/mosquitto_*; do \
        [ -e "$f" ] || continue; \
        strip --strip-unneeded "$f" || true; \
    done

# Stage 3: runtime
FROM alpine:3.23.3
RUN apk add --no-cache ca-certificates libgcc libstdc++ openssl cjson libwebsockets c-ares
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
either replace `build:` with:

```yaml
image: mosquitto:2.1.3-custom
```

or keep a `build:` section that points to `Dockerfile.mosquitto.custom` and pins the SHA:

```yaml
image: mosquitto:2.1.3-custom
build:
  context: ..
  dockerfile: docker/Dockerfile.mosquitto.custom
  args:
    MOSQ_REF: ${MOSQ_REF:-<commit-sha>}
```

## 4) Verify version inside container

```bash
docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml run --rm mosquitto mosquitto -h | head -n 1
```

## 5) Refresh to the latest upstream commit

From the repository root:

```bash
cd /home/eagle/TCC2

MOSQ_REF=$(git ls-remote https://github.com/eclipse-mosquitto/mosquitto.git HEAD | awk '{print $1}')
echo "Using MOSQ_REF=$MOSQ_REF"

MOSQ_REF="$MOSQ_REF" docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml build --pull mosquitto
MOSQ_REF="$MOSQ_REF" docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml up -d --force-recreate mosquitto

docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml run --rm mosquitto mosquitto -h | head -n 1
```

## Notes

- Prefer a commit SHA over a moving branch for reproducibility.
- If you see unexpected password-based auth failures on `CONNECT`, verify the
  broker build first; the plugin does not currently fail fast on an older
  `MOSQ_EVT_BASIC_AUTH` ABI.
- On unreleased commits, `mosquitto -h` may still print `2.1.2` until upstream bumps the version string.
- Keep the image tag explicit (`2.1.3-custom`, `2.1.3-rc`, etc.) to avoid confusion.
- Once `eclipse-mosquitto:2.1.3-alpine` is published, you can switch back to the official image.
