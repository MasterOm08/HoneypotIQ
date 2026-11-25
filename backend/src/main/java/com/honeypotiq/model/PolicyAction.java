package com.honeypotiq.model;

public enum PolicyAction {
    ALLOW_INTERNAL,
    MONITOR_EXTERNAL,
    HONEYPOT_TRAP,
    BLOCK_KNOWN_MALICIOUS
}