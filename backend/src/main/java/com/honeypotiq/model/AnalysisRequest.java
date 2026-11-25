package com.honeypotiq.model;

import java.util.List;
import java.util.Map;

public record AnalysisRequest(
    List<ConnectionEvent> events,
    Map<String, PolicyAction> cidrPolicies, // e.g., {"192.168.1.0/24": "ALLOW_INTERNAL", "10.0.5.0/24": "HONEYPOT_TRAP"}
    int topK,
    long sessionTtlMs,
    long bucketSizeMs,
    Integer queryStartBucket,
    Integer queryEndBucket
) {}