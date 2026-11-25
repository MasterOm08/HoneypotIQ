# HoneypotIQ — Adaptive Port-Scan & Reconnaissance Detection Engine



![Java](https://img.shields.io/badge/Java-17%2B-orange?style=flat-square&logo=openjdk)

![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-brightgreen?style=flat-square&logo=springboot)

![React](https://img.shields.io/badge/React-18%2B-blue?style=flat-square&logo=react)

![JUnit 5](https://img.shields.io/badge/Tests-20%2F20%20Passing-success?style=flat-square&logo=junit5)



**Course:** Advanced Algorithms (CIA 3: Real-World Application Project)  

**Author:** Omsankar Nadar (`2406270`) — B.Tech CS (AI & ML), Semester V  



---



## Overview



**HoneypotIQ** is a real-time network reconnaissance and port-scan detection engine coupled with an interactive Security Operations Center (SOC) dashboard. It processes high-volume network connection metadata and decoy honeypot telemetry to isolate vertical port scans and horizontal subnet sweeps while filtering out authorized internal vulnerability scanners.



All four core data structures and algorithms are implemented **100% from scratch in Java** without relying on standard library collection shortcuts (`TreeMap`, `Arrays.sort`, etc.).



### Core Algorithmic Architecture



| Algorithm / Data Structure | Syllabus Unit & CO | Operational Role in HoneypotIQ | Time Complexity |

| :--- | :--- | :--- | :--- |

| **Bitwise Prefix Trie** | Unit 4 *(Text Search)* | IPv4 CIDR longest-prefix matching ($W = 32$ bits) to classify traffic into allowlists, monitored external zones, and decoy honeypot traps. | $O(W) = O(1)$ |

| **Red-Black Tree** | Unit 3 *(Trees)* | Self-balancing BST keyed by session expiration timestamps to bound memory usage via chronological TTL eviction. | $O(\log N)$ |

| **Segment Tree** | Unit 3 *(Range Queries)* | Point updates and range-sum / range-max queries over discrete time buckets for sliding-window burst detection. | $O(\log M)$ |

| **Randomized Quickselect** | Unit 1 & Unit 6 *(CO5)* | Randomized pivot selection to extract Top-$K$ anomalous scanner IPs without full $O(N \log N)$ sorting. | $O(N)$ expected |



---



## Repository Structure



```text

honeypotiq/
├── backend/
│   ├── pom.xml
│   └── src/
│       ├── main/java/com/honeypotiq/
│       │   ├── HoneypotIqApplication.java
│       │   ├── algorithms/       # BitwisePrefixTrie, RedBlackTree, SegmentTree, RandomizedQuickselect
│       │   ├── baseline/         # NaiveHashMapDetector (O(N log N) baseline for benchmarking)
│       │   ├── controller/       # HoneypotController (REST API endpoints)
│       │   ├── model/            # ConnectionEvent, PolicyAction, SourceRiskScore, DTOs
│       │   └── service/          # DetectionEngineService, BenchmarkService
│       └── test/java/com/honeypotiq/
│           └── AlgorithmSuiteTest.java # 20 JUnit 5 correctness, invariant & boundary tests
├── edge_tests
|   └── data/
│       ├── generate_logs.py          # Synthetic network flow log generator
│       ├── sample_1k.csv             # 1,000-event test dataset
│       ├── sample_10k.csv            # 10,000-event test dataset
│       └── sample_100k.csv           # 100,000-event benchmark dataset
├── frontend/
│   ├── package.json
│   └── src/
│       ├── App.jsx               # SOC Threat Detection & Empirical Benchmark Dashboard
│       └── App.css
└── README.md

```



---



## Prerequisites



* **Java Development Kit (JDK):** Version 17 or higher

* **Build Tool:** Apache Maven 3.8+ (or VS Code Java Extension Pack)

* **Frontend Runtime:** Node.js 18+ and `npm`

* **Data Generator (Optional):** Python 3.8+ *(uses Python standard library only; no `pip` dependencies)*



---



## Quick Start & Run Instructions



### 1. Start the Java Spring Boot Backend

Open `HoneypotIqApplication.java` in VS Code and click **Run**, or execute via terminal:

```bash

cd backend

mvn spring-boot:run

```

> The backend REST API will start on **`http://localhost:8080`**.



### 2. Run the JUnit 5 Test Suite (20 Tests)

Run `AlgorithmSuiteTest.java` via the VS Code Test Explorer, or execute:

```bash

cd backend

mvn test

```



### 3. Start the React SOC Dashboard

```bash

cd frontend

npm install

npm run dev

```

> Open **`http://localhost:5173`** in your browser to view the dashboard.



### 4. Generate Sample Datasets (Optional)

```bash

cd data

python generate_logs.py

```

> Generates `sample_1k.csv`, `sample_10k.csv`, and `sample_100k.csv` with schema:  

> `timestamp_ms,src_ip,dst_ip,dst_port,protocol,tcp_flags`



---



## REST API Reference



| Method | Endpoint | Parameters / Body | Description |

| :--- | :--- | :--- | :--- |

| `GET` | `/api/simulate` | `?size=10000&topK=5&ttlMs=15000` | Generates a synthetic traffic stream and runs the 4-algorithm pipeline. |

| `POST` | `/api/analyze/csv` | `multipart/form-data` (`file`, `topK`, `ttlMs`, `startBucket`, `endBucket`) | Ingests a CSV connection log and returns window metrics & Top-$K$ alerts. |

| `POST` | `/api/analyze` | JSON `AnalysisRequest` (`events` + `cidrPolicies`) | Evaluates custom JSON traffic batches with user-defined CIDR subnet rules. |

| `GET` | `/api/benchmark` | *None* | Runs scaled benchmarks ($N = 1\text{k}, 10\text{k}, 100\text{k}$) against `NaiveHashMapDetector`. |



### Example `cURL` Request (CSV Log Analysis)

```bash

curl -X POST "http://localhost:8080/api/analyze/csv" \

  -F "file=@../data/sample_10k.csv" \

  -F "topK=5" \

  -F "ttlMs=15000"

```



---



## Empirical Verification & Demo Checklist



- [x] **20/20 JUnit 5 Unit & Edge Tests Passing** (5 per core algorithm covering boundary masks, RB-Tree black-height invariants, Segment Tree range bounds, and duplicate-score Quickselect partitioning).

- [x] **SOC Threat Detection Dashboard** displaying Red-Black Tree active/evicted session counts, Segment Tree sliding-window peak intensity, and Randomized Quickselect Top-$K$ attacker triage.

- [x] **Scaled Baseline Comparison** demonstrating latency speedup and bounded session memory over `NaiveHashMapDetector` across $1\text{k}$, $10\text{k}$, and $100\text{k}$ events.
