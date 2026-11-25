import csv
import random
import os

def generate_dataset(filename: str, num_events: int, seed: int = 42):
    rng = random.Random(seed)
    current_ts = 1700000000000  # Base epoch ms

    # Simulated actor profiles
    vertical_scanners = ["45.33.32.156", "185.220.101.4"]      # Probes many ports on one host
    horizontal_scanners = ["91.134.188.22", "203.0.113.77"]   # Sweeps same port across many hosts
    approved_internal = ["192.168.1.50"]                      # Authorized internal scanner (Trie allowlist)
    honeypot_decoys = ["10.0.5.10", "10.0.5.25", "10.0.5.99"] # Decoy traps (Trie honeypot zone)
    production_hosts = [f"172.16.10.{i}" for i in range(1, 30)]
    common_ports = [80, 443, 53, 22, 8080, 3306]

    # Always save in the exact same folder as generate_logs.py
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(script_dir, filename)

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp_ms", "src_ip", "dst_ip", "dst_port", "protocol", "tcp_flags"])

        for _ in range(num_events):
            current_ts += rng.randint(1, 20)
            roll = rng.random()

            if roll < 0.08:
                src = rng.choice(vertical_scanners)
                dst = rng.choice(production_hosts[:3])
                port = rng.randint(1, 16000)
                writer.writerow([current_ts, src, dst, port, "TCP", "SYN"])

            elif roll < 0.14:
                src = rng.choice(horizontal_scanners)
                dst = rng.choice(honeypot_decoys) if rng.random() < 0.35 else rng.choice(production_hosts)
                port = rng.choice([22, 23, 445, 3389])
                writer.writerow([current_ts, src, dst, port, "TCP", "SYN"])

            elif roll < 0.20:
                src = approved_internal[0]
                dst = rng.choice(production_hosts)
                port = rng.randint(1, 1024)
                writer.writerow([current_ts, src, dst, port, "TCP", "SYN"])

            else:
                src = f"203.0.114.{rng.randint(10, 240)}"
                dst = rng.choice(production_hosts)
                port = rng.choice(common_ports)
                writer.writerow([current_ts, src, dst, port, "TCP", "ACK"])

    print(f"Generated {filepath} ({num_events} rows)")

if __name__ == "__main__":
    generate_dataset("sample_1k.csv", 1_000)
    generate_dataset("sample_10k.csv", 10_000)
    generate_dataset("sample_100k.csv", 100_000)