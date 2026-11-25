package com.honeypotiq.algorithms;

import com.honeypotiq.model.PolicyAction;

/**
 * Custom Bitwise Prefix Trie for O(W) IPv4 CIDR Longest Prefix Matching (W = 32 bits).
 * Syllabus Unit 4: Text Search / Tries.
 */
public class BitwisePrefixTrie {

    private static class TrieNode {
        TrieNode[] children = new TrieNode[2]; // 0 = bit 0, 1 = bit 1
        PolicyAction action = null;
        String matchedCidr = null;
    }

    public record PolicyMatch(PolicyAction action, String matchedCidr) {}

    private final TrieNode root;
    private int ruleCount;

    public BitwisePrefixTrie() {
        this.root = new TrieNode();
        this.ruleCount = 0;
    }

    /**
     * Inserts a CIDR block (e.g., "10.0.5.0/24") with an associated PolicyAction.
     * Time Complexity: O(prefixLength) <= O(32) = O(1).
     */
    public void insertCidr(String cidr, PolicyAction action) {
        if (cidr == null || !cidr.contains("/") || action == null) {
            throw new IllegalArgumentException("Invalid CIDR or action: " + cidr);
        }

        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Malformed CIDR notation: " + cidr);
        }

        long ipInt = ipv4ToLong(parts[0]);
        int prefixLength;
        try {
            prefixLength = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid CIDR prefix mask: " + parts[1]);
        }

        if (prefixLength < 0 || prefixLength > 32) {
            throw new IllegalArgumentException("CIDR mask must be between 0 and 32: " + prefixLength);
        }

        TrieNode curr = root;
        for (int i = 31; i >= 32 - prefixLength; i--) {
            int bit = (int) ((ipInt >> i) & 1L);
            if (curr.children[bit] == null) {
                curr.children[bit] = new TrieNode();
            }
            curr = curr.children[bit];
        }

        if (curr.action == null) {
            ruleCount++;
        }
        curr.action = action;
        curr.matchedCidr = cidr;
    }

    /**
     * Finds the deepest matching CIDR rule for a given IPv4 address.
     * Time Complexity: O(32) = O(1), independent of total stored rules.
     */
    public PolicyMatch longestPrefixMatch(String ipv4) {
        long ipInt = ipv4ToLong(ipv4);
        TrieNode curr = root;
        PolicyAction bestAction = PolicyAction.MONITOR_EXTERNAL;
        String bestCidr = "0.0.0.0/0 (DEFAULT)";

        if (curr.action != null) {
            bestAction = curr.action;
            bestCidr = curr.matchedCidr;
        }

        for (int i = 31; i >= 0; i--) {
            int bit = (int) ((ipInt >> i) & 1L);
            if (curr.children[bit] == null) {
                break;
            }
            curr = curr.children[bit];
            if (curr.action != null) {
                bestAction = curr.action;
                bestCidr = curr.matchedCidr;
            }
        }
        return new PolicyMatch(bestAction, bestCidr);
    }

    public int getRuleCount() {
        return ruleCount;
    }

    /**
     * Converts dotted-decimal IPv4 string to unsigned 32-bit integer stored in a long.
     */
    public static long ipv4ToLong(String ip) {
        if (ip == null || ip.isBlank()) {
            throw new IllegalArgumentException("IP address cannot be null or empty");
        }
        String[] octets = ip.trim().split("\\.");
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 format: " + ip);
        }
        long result = 0;
        for (String octetStr : octets) {
            int octet;
            try {
                octet = Integer.parseInt(octetStr);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Non-numeric octet in IPv4: " + ip);
            }
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException("Octet out of range [0-255] in IPv4: " + ip);
            }
            result = (result << 8) | octet;
        }
        return result;
    }
}