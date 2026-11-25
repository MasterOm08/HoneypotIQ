package com.honeypotiq.controller;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.honeypotiq.model.AnalysisRequest;
import com.honeypotiq.model.AnalysisResponse;
import com.honeypotiq.model.BenchmarkResult;
import com.honeypotiq.model.ConnectionEvent;
import com.honeypotiq.model.PolicyAction;
import com.honeypotiq.service.BenchmarkService;
import com.honeypotiq.service.DetectionEngineService;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class HoneypotController {

    private final DetectionEngineService detectionService;
    private final BenchmarkService benchmarkService;

    public HoneypotController(DetectionEngineService detectionService,
                              BenchmarkService benchmarkService) {
        this.detectionService = detectionService;
        this.benchmarkService = benchmarkService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzeJson(@RequestBody AnalysisRequest request) {
        try {
            return ResponseEntity.ok(detectionService.runDetection(request));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/analyze/csv")
    public ResponseEntity<?> analyzeCsv(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "topK", defaultValue = "5") int topK,
            @RequestParam(value = "ttlMs", defaultValue = "30000") long ttlMs,
            @RequestParam(value = "bucketSizeMs", defaultValue = "1000") long bucketSizeMs,
            @RequestParam(value = "startBucket", required = false) Integer startBucket,
            @RequestParam(value = "endBucket", required = false) Integer endBucket) {

        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Uploaded CSV file is empty."));
        }

        try {
            List<ConnectionEvent> events = parseCsv(file);
            Map<String, PolicyAction> defaultPolicies = Map.of(
                "192.168.1.0/24", PolicyAction.ALLOW_INTERNAL,
                "10.0.5.0/24", PolicyAction.HONEYPOT_TRAP,
                "172.16.0.0/16", PolicyAction.MONITOR_EXTERNAL
            );

            AnalysisRequest request = new AnalysisRequest(
                events, defaultPolicies, topK, ttlMs, bucketSizeMs, startBucket, endBucket
            );
            return ResponseEntity.ok(detectionService.runDetection(request));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid CSV format: " + e.getMessage()));
        }
    }

    @GetMapping("/simulate")
    public ResponseEntity<AnalysisResponse> runDemoSimulation(
            @RequestParam(value = "size", defaultValue = "5000") int size,
            @RequestParam(value = "topK", defaultValue = "5") int topK,
            @RequestParam(value = "ttlMs", defaultValue = "15000") long ttlMs) {

        int safeSize = Math.max(10, Math.min(size, 200_000));
        List<ConnectionEvent> events = benchmarkService.generateSyntheticDataset(safeSize, System.currentTimeMillis());

        Map<String, PolicyAction> defaultPolicies = Map.of(
            "192.168.1.0/24", PolicyAction.ALLOW_INTERNAL,
            "10.0.5.0/24", PolicyAction.HONEYPOT_TRAP,
            "172.16.0.0/16", PolicyAction.MONITOR_EXTERNAL
        );

        AnalysisRequest request = new AnalysisRequest(events, defaultPolicies, topK, ttlMs, 1000L, null, null);
        return ResponseEntity.ok(detectionService.runDetection(request));
    }

    @GetMapping("/benchmark")
    public ResponseEntity<List<BenchmarkResult>> runBenchmarks() {
        return ResponseEntity.ok(benchmarkService.runScaledBenchmarks());
    }

    private List<ConnectionEvent> parseCsv(MultipartFile file) throws Exception {
        List<ConnectionEvent> events = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            boolean isHeader = true;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) continue;
                if (isHeader && line.toLowerCase().startsWith("timestamp")) {
                    isHeader = false;
                    continue;
                }
                isHeader = false;
                String[] cols = line.split(",");
                if (cols.length < 6) {
                    throw new IllegalArgumentException("Expected 6 CSV columns: timestamp_ms,src_ip,dst_ip,dst_port,protocol,tcp_flags");
                }
                events.add(new ConnectionEvent(
                    Long.parseLong(cols[0].trim()),
                    cols[1].trim(),
                    cols[2].trim(),
                    Integer.parseInt(cols[3].trim()),
                    cols[4].trim(),
                    cols[5].trim()
                ));
            }
        }
        return events;
    }
}