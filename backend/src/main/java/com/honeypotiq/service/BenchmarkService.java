package com.honeypotiq.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.springframework.stereotype.Service;

import com.honeypotiq.baseline.NaiveHashMapDetector;
import com.honeypotiq.model.AnalysisRequest;
import com.honeypotiq.model.AnalysisResponse;
import com.honeypotiq.model.BenchmarkResult;
import com.honeypotiq.model.ConnectionEvent;
import com.honeypotiq.model.PolicyAction;

@Service
public class BenchmarkService {

    private final DetectionEngineService detectionEngineService;
    private final NaiveHashMapDetector baselineDetector;

    public BenchmarkService(DetectionEngineService detectionEngineService) {
        this.detectionEngineService = detectionEngineService;
        this.baselineDetector = new NaiveHashMapDetector();
    }

    public List<BenchmarkResult> runScaledBenchmarks() {
        int[] scales = {1_000, 10_000, 100_000};
        List<BenchmarkResult> results = new ArrayList<>();

        Map<String, PolicyAction> defaultPolicies = Map.of(
            "192.168.1.0/24", PolicyAction.ALLOW_INTERNAL,
            "10.0.5.0/24", PolicyAction.HONEYPOT_TRAP,
            "172.16.0.0/16", PolicyAction.MONITOR_EXTERNAL
        );

        for (int n : scales) {
            List<ConnectionEvent> syntheticEvents = generateSyntheticDataset(n, 42L);
            AnalysisRequest req = new AnalysisRequest(
                syntheticEvents, defaultPolicies, 10, 15_000L, 1_000L, 0, null
            );

            // Warmup & measure HoneypotIQ
            System.gc();
            long memBeforeHq = usedMemory();
            long t0 = System.nanoTime();
            AnalysisResponse hqResp = detectionEngineService.runDetection(req);
            long hqMicros = (System.nanoTime() - t0) / 1_000L;
            long memAfterHq = Math.max(1024L, usedMemory() - memBeforeHq);

            // Measure Naive Baseline
            System.gc();
            long memBeforeBase = usedMemory();
            long t1 = System.nanoTime();
            NaiveHashMapDetector.BaselineOutput baseResp = baselineDetector.analyze(
                syntheticEvents, defaultPolicies, 10, 0L, Long.MAX_VALUE
            );
            long baseMicros = (System.nanoTime() - t1) / 1_000L;
            long memAfterBase = Math.max(1024L, usedMemory() - memBeforeBase);

            double speedup = hqMicros > 0 ? Math.round(((double) baseMicros / hqMicros) * 100.0) / 100.0 : 1.0;

            results.add(new BenchmarkResult(
                n,
                hqMicros,
                baseMicros,
                speedup,
                memAfterHq,
                memAfterBase,
                hqResp.activeSessionsRetained(),
                baseResp.retainedEventCount()
            ));
        }

        return results;
    }

    public List<ConnectionEvent> generateSyntheticDataset(int count, long seed) {
        Random rng = new Random(seed);
        List<ConnectionEvent> events = new ArrayList<>(count);
        long currentTs = 1_700_000_000_000L;

        String[] scanners = {"45.33.32.156", "185.220.101.4", "91.134.188.22", "203.0.113.77"};
        String[] benignHosts = {"172.16.10.5", "172.16.10.8", "172.16.12.14", "172.16.15.20"};
        String[] internalApproved = {"192.168.1.50"};
        String[] honeypotTargets = {"10.0.5.10", "10.0.5.25"};
        int[] commonPorts = {80, 443, 53, 22, 8080};

        for (int i = 0; i < count; i++) {
            currentTs += rng.nextInt(25) + 1;
            double roll = rng.nextDouble();

            if (roll < 0.15) {
                // Injected port scanner probing random ports and honeypots
                String scanner = scanners[rng.nextInt(scanners.length)];
                String target = (rng.nextDouble() < 0.3)
                    ? honeypotTargets[rng.nextInt(honeypotTargets.length)]
                    : benignHosts[rng.nextInt(benignHosts.length)];
                int port = 1 + rng.nextInt(10000);
                events.add(new ConnectionEvent(currentTs, scanner, target, port, "TCP", "SYN"));
            } else if (roll < 0.22) {
                // Approved internal vulnerability scanner (should be filtered by Prefix Trie)
                events.add(new ConnectionEvent(
                    currentTs, internalApproved[0], benignHosts[0], 1 + rng.nextInt(1024), "TCP", "SYN"
                ));
            } else {
                // Normal benign user traffic
                String normalSrc = "203.0.114." + (10 + rng.nextInt(200));
                String dst = benignHosts[rng.nextInt(benignHosts.length)];
                int port = commonPorts[rng.nextInt(commonPorts.length)];
                events.add(new ConnectionEvent(currentTs, normalSrc, dst, port, "TCP", "ACK"));
            }
        }
        return events;
    }

    private long usedMemory() {
        Runtime rt = Runtime.getRuntime();
        return rt.totalMemory() - rt.freeMemory();
    }
}