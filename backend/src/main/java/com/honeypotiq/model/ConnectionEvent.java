package com.honeypotiq.model;

public record ConnectionEvent(
    long timestampMs,
    String srcIp,
    String dstIp,
    int dstPort,
    String protocol,
    String tcpFlags
) {
    public ConnectionEvent {
        if (timestampMs < 0) {
            throw new IllegalArgumentException("Timestamp cannot be negative");
        }
        if (srcIp == null || srcIp.isBlank() || dstIp == null || dstIp.isBlank()) {
            throw new IllegalArgumentException("Source and destination IPs cannot be empty");
        }
        if (dstPort < 0 || dstPort > 65535) {
            throw new IllegalArgumentException("Invalid destination port: " + dstPort);
        }
    }
}