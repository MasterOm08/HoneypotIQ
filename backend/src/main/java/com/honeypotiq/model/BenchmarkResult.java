package com.honeypotiq.model;

public record BenchmarkResult(
    int datasetSize,
    long honeypotIqTimeMicros,
    long baselineTimeMicros,
    double speedupFactor,
    long honeypotIqMemoryBytes,
    long baselineMemoryBytes,
    int activeSessionsAfterEviction,
    int baselineRetainedRecords
) {}