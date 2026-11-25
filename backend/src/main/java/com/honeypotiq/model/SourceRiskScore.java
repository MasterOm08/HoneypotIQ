package com.honeypotiq.model;

public class SourceRiskScore {
    private final String srcIp;
    private final int uniquePortsProbed;
    private final int uniqueHostsProbed;
    private final int honeypotHits;
    private final int totalEvents;
    private final double riskScore;
    private final PolicyAction policyAction;

    public SourceRiskScore(String srcIp, int uniquePortsProbed, int uniqueHostsProbed,
                           int honeypotHits, int totalEvents, PolicyAction policyAction) {
        this.srcIp = srcIp;
        this.uniquePortsProbed = uniquePortsProbed;
        this.uniqueHostsProbed = uniqueHostsProbed;
        this.honeypotHits = honeypotHits;
        this.totalEvents = totalEvents;
        this.policyAction = policyAction;
        // Weighted anomaly score: vertical port scan + horizontal host sweep + heavy penalty for honeypot hits
        this.riskScore = (uniquePortsProbed * 2.5) + (uniqueHostsProbed * 3.0) + (honeypotHits * 15.0) + (totalEvents * 0.2);
    }

    public String getSrcIp() { return srcIp; }
    public int getUniquePortsProbed() { return uniquePortsProbed; }
    public int getUniqueHostsProbed() { return uniqueHostsProbed; }
    public int getHoneypotHits() { return honeypotHits; }
    public int getTotalEvents() { return totalEvents; }
    public double getRiskScore() { return riskScore; }
    public PolicyAction getPolicyAction() { return policyAction; }
}