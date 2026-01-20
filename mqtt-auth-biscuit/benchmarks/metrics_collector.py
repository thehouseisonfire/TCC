import argparse
import json
import statistics
import time

import paho.mqtt.client as mqtt


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
            print(f"      Connection failed with code {rc}")

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
        print(f"      Failed to connect: {e}")
        return []

    client.loop_start()

    for i in range(message_count):
        userdata["start_time"] = time.time()
        res = client.publish(topic, f"msg {i}", qos=1)
        if res.rc != mqtt.MQTT_ERR_SUCCESS:
            print(f"      Publish error: {res.rc}")
        time.sleep(0.01)

    time.sleep(1)  # Wait for final messages
    client.loop_stop()
    client.disconnect()

    return latencies


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--tls-ca-file")
    ap.add_argument("--tls-insecure", action="store_true")
    ap.add_argument("--messages", type=int, default=100)
    args = ap.parse_args()

    with open("benchmarks/tokens.json", "r") as f:
        tokens = json.load(f)

    results = {}

    for token_type in ["jwt", "biscuit"]:
        print(f"Benchmarking {token_type}...")
        latencies = run_benchmark(
            args.host,
            args.port,
            token_type,
            tokens[token_type],
            "sensors/client_1/temp",
            message_count=args.messages,
            tls_enabled=args.tls,
            tls_ca_file=args.tls_ca_file,
            tls_insecure=args.tls_insecure,
        )
        results[token_type] = {
            "median": statistics.median(latencies) * 1000,
            "mean": statistics.mean(latencies) * 1000,
            "stdev": statistics.stdev(latencies) * 1000 if len(latencies) > 1 else 0,
        }
        print(f"  Median: {results[token_type]['median']:.2f} ms")
        print(f"  Mean:   {results[token_type]['mean']:.2f} ms")

    with open("benchmarks/results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to benchmarks/results.json")
