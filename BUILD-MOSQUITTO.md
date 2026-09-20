# Build the Custom Mosquitto Image

The benchmark builds Mosquitto from a pinned upstream commit because the
official `eclipse-mosquitto:2.1.3-alpine` image is not yet available and the
plugin requires a newer authentication-event ABI than `2.1.2-alpine` provides.

This migration requires Mosquitto commit `43c271504277941a4423a7e8c6b07bbcb611080b`
or newer so `MOSQ_EVT_BASIC_AUTH` exposes `password_len` for binary `CONNECT`
passwords.

Older brokers are unsupported with the current plugin. The auth path now
assumes the newer `MOSQ_EVT_BASIC_AUTH` layout at runtime, so using an older
broker may fail later as confusing `CONNECT` authentication errors rather than
as a clean startup error.

## 1) Pinned Dockerfile

The tracked `mqtt-auth-biscuit/docker/Dockerfile.mosquitto.custom` is the
canonical image definition:

```dockerfile
# Stage 1: build Rust plugin (.so)
FROM rust:1.93.1-alpine@sha256:4fec02de605563c297c78a31064c8335bc004fa2b0bf406b1b99441da64e2d2d AS plugin-builder
RUN apk add --no-cache build-base=0.5-r3 cmake=4.1.3-r0 perl=5.42.2-r0 musl-dev=1.2.5-r23
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/mosquitto-plugin ./crates/mosquitto-plugin
COPY crates/token-issuer ./crates/token-issuer
COPY crates/authz-server ./crates/authz-server
RUN printf '[workspace]\nmembers = ["crates/mosquitto-plugin"]\nresolver = "2"\n' > Cargo.toml
RUN RUSTFLAGS="-C target-feature=-crt-static -C strip=symbols" cargo build --release -p mosquitto-auth-biscuit
RUN strip --strip-unneeded /app/target/release/libmosquitto_auth_biscuit.so

# Stage 2: build Mosquitto from source
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS mosq-builder
ARG MOSQ_REF=b3b4d77ef3faef6dfcdfac3fb00a9b5a42859aca
RUN apk add --no-cache git=2.52.0-r0 build-base=0.5-r3 cmake=4.1.3-r0 openssl-dev=3.5.8-r0 cjson-dev=1.7.19-r1 libwebsockets-dev=4.3.5-r2 c-ares-dev=1.34.8-r0
RUN git clone https://github.com/eclipse-mosquitto/mosquitto.git /src
WORKDIR /src
RUN git checkout "${MOSQ_REF}"
RUN make -j"$(nproc)" prefix=/usr WITH_SHARED_LIBRARIES=yes WITH_DOCS=no WITH_EDITLINE=no WITH_HTTP_API=no WITH_SQLITE=no
RUN make prefix=/usr WITH_SHARED_LIBRARIES=yes WITH_DOCS=no WITH_EDITLINE=no WITH_HTTP_API=no WITH_SQLITE=no install DESTDIR=/out
RUN set -eux; \
    for f in /out/usr/sbin/mosquitto /out/usr/lib/libmosquitto.so.1 /out/usr/lib/libmosquitto_common.so.1 /out/usr/lib/mosquitto_*.so /out/usr/bin/mosquitto_*; do \
        [ -e "$f" ] || continue; \
        strip --strip-unneeded "$f" || true; \
    done

# Stage 3: runtime
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
RUN apk add --no-cache ca-certificates libgcc=15.2.0-r2 libstdc++=15.2.0-r2 openssl=3.5.8-r0 cjson=1.7.19-r1 libwebsockets=4.3.5-r2 c-ares=1.34.8-r0
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

## 5) Test a newer upstream commit

Do not replace the committed default merely because upstream `HEAD` changed.
For an explicit compatibility test, resolve the candidate SHA and pass it only
to that build:

```bash
MOSQ_REF=$(git ls-remote https://github.com/eclipse-mosquitto/mosquitto.git HEAD | awk '{print $1}')
echo "Using MOSQ_REF=$MOSQ_REF"

MOSQ_REF="$MOSQ_REF" docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml build --pull mosquitto
MOSQ_REF="$MOSQ_REF" docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml up -d --force-recreate mosquitto

docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml run --rm mosquitto mosquitto -h | head -n 1
```

## Notes

- Prefer a commit SHA over a moving branch for reproducibility.
- Update the Dockerfile default only after the newer SHA passes plugin and
  broker integration tests.
- If you see unexpected password-based auth failures on `CONNECT`, verify the
  broker build first; the plugin does not currently fail fast on an older
  `MOSQ_EVT_BASIC_AUTH` ABI.
- On unreleased commits, `mosquitto -h` may still print `2.1.2` until upstream bumps the version string.
- Keep the image tag explicit (`2.1.3-custom`, `2.1.3-rc`, etc.) to avoid confusion.
- Once `eclipse-mosquitto:2.1.3-alpine` is published, you can switch back to the official image.
