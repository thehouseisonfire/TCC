import paho.mqtt.client as mqtt
import time
import statistics
import json

def run_benchmark(host, port, username, password, topic, message_count=1000):
    latencies = []
    
    def on_publish(client, userdata, mid):
        latencies.append(time.time() - userdata['start_time'])

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc != 0:
            print(f"      Connection failed with code {rc}")

    def on_publish(client, userdata, mid, reason_code=None, properties=None):
        latencies.append(time.time() - userdata['start_time'])

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="client_1")
    client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.on_publish = on_publish
    
    userdata = {'start_time': 0}
    client.user_data_set(userdata)
    
    try:
        client.connect(host, port, 60)
    except Exception as e:
        print(f"      Failed to connect: {e}")
        return []

    client.loop_start()
    
    for i in range(message_count):
        userdata['start_time'] = time.time()
        res = client.publish(topic, f"msg {i}", qos=1)
        if res.rc != mqtt.MQTT_ERR_SUCCESS:
            print(f"      Publish error: {res.rc}")
        time.sleep(0.01)
        
    time.sleep(1) # Wait for final messages
    client.loop_stop()
    client.disconnect()
    
    return latencies

if __name__ == "__main__":
    with open("benchmarks/tokens.json", "r") as f:
        tokens = json.load(f)
    
    results = {}
    
    for token_type in ["jwt", "biscuit"]:
        print(f"Benchmarking {token_type}...")
        latencies = run_benchmark("localhost", 1883, token_type, tokens[token_type], f"sensors/client_1/temp", message_count=100)
        results[token_type] = {
            "median": statistics.median(latencies) * 1000,
            "mean": statistics.mean(latencies) * 1000,
            "stdev": statistics.stdev(latencies) * 1000 if len(latencies) > 1 else 0
        }
        print(f"  Median: {results[token_type]['median']:.2f} ms")
        print(f"  Mean:   {results[token_type]['mean']:.2f} ms")

    with open("benchmarks/results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to benchmarks/results.json")
