package com.honeypotiq.baseline;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.honeypotiq.model.ConnectionEvent;
import com.honeypotiq.model.PolicyAction;
import com.honeypotiq.model.SourceRiskScore;

/**
 * Conventional Baseline Detector for empirical comparison against HoneypotIQ:
 * - Uses flat HashMap per-source counters with no TTL eviction (unbounded memory).
 * - Evaluates time-window intensity via linear O(N) scan over all stored events.
 * - Ranks suspicious sources via full O(N log N) comparison sort.
 */
public class NaiveHashMapDetector {

    public record BaselineOutput(
        long windowIntensity,
        List<SourceRiskScore> topK,
        int retainedEventCount
    ) {}

    public BaselineOutput analyze(List<ConnectionEvent> events,
                                  Map<String, PolicyAction> cidrPolicies,
                                  int topK,
                                  long windowStartMs,
                                  long windowEndMs) {
        if (events == null || events.isEmpty()) {
            return new BaselineOutput(0L, List.of(), 0);
        }

        // Retain all raw events in memory (no Red-Black Tree TTL eviction)
        List<ConnectionEvent> allStoredEvents = new ArrayList<>(events);

        // 1. Linear O(N) scan for time-window intensity
        long windowCount = 0;
        for (ConnectionEvent e : allStoredEvents) {
            if (e.timestampMs() >= windowStartMs && e.timestampMs() <= windowEndMs) {
                windowCount++;
            }
        }

        // 2. Aggregate per-source counters via HashMap
        Map<String, Set<Integer>> portsBySrc = new HashMap<>();
        Map<String, Set<String>> hostsBySrc = new HashMap<>();
        Map<String, Integer> honeypotHitsBySrc = new HashMap<>();
        Map<String, Integer> totalBySrc = new HashMap<>();

        for (ConnectionEvent e : allStoredEvents) {
            String src = e.srcIp();
            portsBySrc.computeIfAbsent(src, k -> new HashSet<>()).add(e.dstPort());
            hostsBySrc.computeIfAbsent(src, k -> new HashSet<>()).add(e.dstIp());
            totalBySrc.merge(src, 1, Integer::sum);

            // Linear scan over CIDR policy rules (naive string prefix check)
            PolicyAction action = resolvePolicyLinear(e.dstIp(), cidrPolicies);
            if (action == PolicyAction.HONEYPOT_TRAP) {
                honeypotHitsBySrc.merge(src, 1, Integer::sum);
            }
        }

        // 3. Full O(N log N) sort across all sources
        List<SourceRiskScore> allScores = new ArrayList<>();
        for (String src : totalBySrc.keySet()) {
            PolicyAction srcPolicy = resolvePolicyLinear(src, cidrPolicies);
            allScores.add(new SourceRiskScore(
                src,
                portsBySrc.get(src).size(),
                hostsBySrc.get(src).size(),
                honeypotHitsBySrc.getOrDefault(src, 0),
                totalBySrc.get(src),
                srcPolicy
            ));
        }

        allScores.sort((a, b) -> Double.compare(b.getRiskScore(), a.getRiskScore()));
        List<SourceRiskScore> topResult = allScores.subList(0, Math.min(topK, allScores.size()));

        return new BaselineOutput(windowCount, topResult, allStoredEvents.size());
    }

    private PolicyAction resolvePolicyLinear(String ip, Map<String, PolicyAction> policies) {
        if (policies == null || policies.isEmpty()) {
            return PolicyAction.MONITOR_EXTERNAL;
        }
        for (Map.Entry<String, PolicyAction> entry : policies.entrySet()) {
            String prefix = entry.getKey().split("/")[0];
            String subnetPrefix = prefix.substring(0, prefix.lastIndexOf('.'));
            if (ip.startsWith(subnetPrefix)) {
                return entry.getValue();
            }
        }
        return PolicyAction.MONITOR_EXTERNAL;
    }
}