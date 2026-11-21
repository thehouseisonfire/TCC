# Build the custom Mosquitto image

Compose uses the repository-pinned Mosquitto source build. The plugin reads
`MOSQ_EVT_BASIC_AUTH.password_len` to handle binary MQTT CONNECT passwords,
which requires upstream commit `43c271504277941a4423a7e8c6b07bbcb611080b` or a
revision that includes that change. An older event ABI can surface as a
password-authentication failure during CONNECT.

The [Compose file](mqtt-auth-biscuit/docker/docker-compose.yml) sets the
`MOSQ_REF` build argument. The [Dockerfile](mqtt-auth-biscuit/docker/Dockerfile.mosquitto.custom)
defines the base images, package pins, and build steps for both the broker and
the plugin.

## Build and check the configured image

From the repository root:

```bash
docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml build mosquitto
docker compose -f mqtt-auth-biscuit/docker/docker-compose.yml   run --rm --no-deps mosquitto /usr/sbin/mosquitto -h | head -n 1
```

The help output reports the broker version string. Record the source commit
and local image ID for benchmark provenance, since builds from different
commits can share a version string. See the image-freeze instructions in the
[benchmark runbook](mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md#frozen-docker-images).

## Test another upstream revision

Set `MOSQ_REF` to a full commit SHA for the build and validate it with the
plugin and broker integration tests before changing the committed pin.
Use a separate image tag for the candidate so it cannot replace the benchmark
image under the same tag:

```bash
docker build -f mqtt-auth-biscuit/docker/Dockerfile.mosquitto.custom \
  --build-arg "MOSQ_REF=${MOSQ_TEST_REF:?Set MOSQ_TEST_REF to the candidate commit SHA}" \
  -t mosquitto:abi-test mqtt-auth-biscuit
```
