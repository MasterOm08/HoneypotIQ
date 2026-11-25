package com.honeypotiq.model;

import java.util.List;

public record AnalysisResponse(
    int totalEventsProcessed,
    int activeSessionsRetained,
    int expiredSessionsEvicted,
    long windowTotalIntensity,
    long windowPeakBucketIntensity,
    int totalTimeBuckets,
    List<SourceRiskScore> topSuspiciousSources,
    long executionTimeMicros
) {}