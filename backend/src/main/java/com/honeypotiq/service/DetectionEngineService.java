package com.honeypotiq.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Service;

import com.honeypotiq.algorithms.BitwisePrefixTrie;
import com.honeypotiq.algorithms.RandomizedQuickselect;
import com.honeypotiq.algorithms.RedBlackTree;
import com.honeypotiq.algorithms.SegmentTree;
import com.honeypotiq.model.AnalysisRequest;
import com.honeypotiq.model.AnalysisResponse;
import com.honeypotiq.model.ConnectionEvent;
import com.honeypotiq.model.PolicyAction;
import com.honeypotiq.model.SourceRiskScore;

@Service
public class DetectionEngineService {

    public AnalysisResponse runDetection(AnalysisRequest request) {
        if (request == null || request.events() == null || request.events().isEmpty()) {
            return new AnalysisResponse(0, 0, 0, 0, 0, 0, List.of(), 0);
        }

        long startTimeNs = System.nanoTime();

        List<ConnectionEvent> events = request.events();
        int topK = request.topK() > 0 ? request.topK() : 5;
        long ttlMs = request.sessionTtlMs() > 0 ? request.sessionTtlMs() : 60_000L;
        long bucketSizeMs = request.bucketSizeMs() > 0 ? request.bucketSizeMs() : 1_000L;

        // 1. Build Bitwise Prefix Trie for CIDR network policy & honeypot zone lookup
        BitwisePrefixTrie policyTrie = new BitwisePrefixTrie();
        if (request.cidrPolicies() != null) {
            for (Map.Entry<String, PolicyAction> entry : request.cidrPolicies().entrySet()) {
                policyTrie.insertCidr(entry.getKey(), entry.getValue());
            }
        }

        // Determine timeline span for Segment Tree buckets
        long minTs = Long.MAX_VALUE;
        long maxTs = Long.MIN_VALUE;
        for (ConnectionEvent e : events) {
            if (e.timestampMs() < minTs) minTs = e.timestampMs();
            if (e.timestampMs() > maxTs) maxTs = e.timestampMs();
        }

        int numBuckets = (int) Math.max(1, ((maxTs - minTs) / bucketSizeMs) + 1);
        SegmentTree segmentTree = new SegmentTree(numBuckets);
        RedBlackTree<ConnectionEvent> sessionTree = new RedBlackTree<>();

        Map<String, Set<Integer>> uniquePorts = new HashMap<>();
        Map<String, Set<String>> uniqueHosts = new HashMap<>();
        Map<String, Integer> honeypotHits = new HashMap<>();
        Map<String, Integer> eventCounts = new HashMap<>();
        Set<String> deduplicationSet = new HashSet<>();

        int expiredCount = 0;

        for (ConnectionEvent event : events) {
            // Deduplicate identical event tuples at the same millisecond
            String dedupKey = event.timestampMs() + "|" + event.srcIp() + "|" + event.dstIp() + "|" + event.dstPort();
            if (!deduplicationSet.add(dedupKey)) {
                continue;
            }

            // Classify source and destination using O(32) Bitwise Prefix Trie
            PolicyAction srcPolicy = policyTrie.longestPrefixMatch(event.srcIp()).action();
            PolicyAction dstPolicy = policyTrie.longestPrefixMatch(event.dstIp()).action();

            // Skip trusted internal scanners unless they hit a honeypot trap
            if (srcPolicy == PolicyAction.ALLOW_INTERNAL && dstPolicy != PolicyAction.HONEYPOT_TRAP) {
                continue;
            }

            // Insert into Red-Black Tree with TTL expiration and evict expired sessions
            sessionTree.insert(event.timestampMs() + ttlMs, event);
            expiredCount += sessionTree.evictExpired(event.timestampMs()).size();

            // Update Segment Tree bucket intensity in O(log M)
            int bucketIdx = (int) ((event.timestampMs() - minTs) / bucketSizeMs);
            long weight = (dstPolicy == PolicyAction.HONEYPOT_TRAP) ? 5L : 1L;
            segmentTree.update(bucketIdx, weight);

            // Track per-source behavioral features
            String src = event.srcIp();
            uniquePorts.computeIfAbsent(src, k -> new HashSet<>()).add(event.dstPort());
            uniqueHosts.computeIfAbsent(src, k -> new HashSet<>()).add(event.dstIp());
            eventCounts.merge(src, 1, Integer::sum);
            if (dstPolicy == PolicyAction.HONEYPOT_TRAP) {
                honeypotHits.merge(src, 1, Integer::sum);
            }
        }

        // Query Segment Tree over requested sliding window [L, R]
        int leftBucket = (request.queryStartBucket() != null)
            ? Math.max(0, Math.min(request.queryStartBucket(), numBuckets - 1)) : 0;
        int rightBucket = (request.queryEndBucket() != null)
            ? Math.max(leftBucket, Math.min(request.queryEndBucket(), numBuckets - 1)) : numBuckets - 1;

        long windowTotal = segmentTree.queryRangeSum(leftBucket, rightBucket);
        long windowPeak = segmentTree.queryRangeMax(leftBucket, rightBucket);

        // Compute candidate risk scores
        List<SourceRiskScore> candidates = new ArrayList<>();
        for (String src : eventCounts.keySet()) {
            PolicyAction action = policyTrie.longestPrefixMatch(src).action();
            candidates.add(new SourceRiskScore(
                src,
                uniquePorts.get(src).size(),
                uniqueHosts.get(src).size(),
                honeypotHits.getOrDefault(src, 0),
                eventCounts.get(src),
                action
            ));
        }

        // Extract Top-K scanners using Randomized Quickselect (Unit 6 / CO5) in expected O(N)
        RandomizedQuickselect quickselect = new RandomizedQuickselect();
        List<SourceRiskScore> topSources = quickselect.selectTopK(candidates, topK);

        long elapsedMicros = (System.nanoTime() - startTimeNs) / 1_000L;

        return new AnalysisResponse(
            events.size(),
            sessionTree.size(),
            expiredCount,
            windowTotal,
            windowPeak,
            numBuckets,
            topSources,
            elapsedMicros
        );
    }
}