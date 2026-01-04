import paho.mqtt.client as mqtt
import time
import statistics
import json

def run_benchmark(host, port, username, password, topic, message_count=100):
    latencies = []
    
    def on_publish(client, userdata, mid):
        latencies.append(time.time() - userdata['start_time'])

    client = mqtt.Client()
    client.username_pw_set(username, password)
    client.on_publish = on_publish
    
    userdata = {'start_time': 0}
    client.user_data_set(userdata)
    
    client.connect(host, port)
    client.loop_start()
    
    for i in range(message_count):
        userdata['start_time'] = time.time()
        client.publish(topic, f"msg {i}", qos=1)
        time.sleep(0.01) # Small delay
        
    client.loop_stop()
    client.disconnect()
    
    return latencies

if __name__ == "__main__":
    # Example usage
    # latencies = run_benchmark("localhost", 1883, "jwt", "eyJ...", "sensors/client_1/temp")
    # print(f"Median latency: {statistics.median(latencies)}")
    pass
