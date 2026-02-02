import json
import statistics
import time

import paho.mqtt.client as mqtt
import typer

from logging_utils import get_logger, setup_logging


logger = get_logger(__name__)
app = typer.Typer(add_completion=False)


def run_benchmark(
    host,
    port,
    username,
    password,
    topic,
    message_count=1000,
    tls_enabled=False,
    tls_ca_file=None,
    tls_insecure=False,
):
    latencies = []

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc != 0:
            logger.warning("Connection failed with code %s", rc)

    def on_publish(client, userdata, mid, reason_code=None, properties=None):
        latencies.append(time.time() - userdata["start_time"])

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="client_1")
    client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.on_publish = on_publish
    if tls_enabled:
        if tls_ca_file:
            client.tls_set(ca_certs=tls_ca_file)
        else:
            client.tls_set()
        if tls_insecure:
            client.tls_insecure_set(True)

    userdata = {"start_time": 0}
    client.user_data_set(userdata)

    try:
        client.connect(host, port, 60)
    except Exception as e:
        logger.error("Failed to connect: %s", e)
        return []

    client.loop_start()

    for i in range(message_count):
        userdata["start_time"] = time.time()
        res = client.publish(topic, f"msg {i}", qos=1)
        if res.rc != mqtt.MQTT_ERR_SUCCESS:
            logger.warning("Publish error: %s", res.rc)
        time.sleep(0.01)

    time.sleep(1)  # Wait for final messages
    client.loop_stop()
    client.disconnect()

    return latencies


@app.command()
def main(
    host: str = "localhost",
    port: int = 1883,
    tls: bool = False,
    tls_ca_file: str | None = None,
    tls_insecure: bool = False,
    messages: int = 100,
    log_level: str = typer.Option("INFO", "--log-level"),
):
    setup_logging(log_level)
    with open("benchmarks/tokens.json", "r") as f:
        tokens = json.load(f)

    results = {}

    for token_type in ["jwt", "biscuit"]:
        logger.info("Benchmarking %s...", token_type)
        latencies = run_benchmark(
            host,
            port,
            token_type,
            tokens[token_type],
            "sensors/client_1/temp",
            message_count=messages,
            tls_enabled=tls,
            tls_ca_file=tls_ca_file,
            tls_insecure=tls_insecure,
        )
        results[token_type] = {
            "median": statistics.median(latencies) * 1000,
            "mean": statistics.mean(latencies) * 1000,
            "stdev": statistics.stdev(latencies) * 1000 if len(latencies) > 1 else 0,
        }
        logger.info("Median: %.2f ms", results[token_type]["median"])
        logger.info("Mean:   %.2f ms", results[token_type]["mean"])

    with open("benchmarks/results.json", "w") as f:
        json.dump(results, f, indent=2)
    logger.info("Results saved to benchmarks/results.json")


if __name__ == "__main__":
    app()
