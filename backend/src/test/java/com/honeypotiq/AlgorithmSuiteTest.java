package com.honeypotiq;

import com.honeypotiq.algorithms.BitwisePrefixTrie;
import com.honeypotiq.algorithms.RandomizedQuickselect;
import com.honeypotiq.algorithms.RedBlackTree;
import com.honeypotiq.algorithms.SegmentTree;
import com.honeypotiq.model.PolicyAction;
import com.honeypotiq.model.SourceRiskScore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AlgorithmSuiteTest {

    // =========================================================================
    // 1. BITWISE PREFIX TRIE TESTS (Unit 4: Text Search / CIDR LPM)
    // =========================================================================
    @Nested
    @DisplayName("1. BitwisePrefixTrie Correctness & Boundary Tests")
    class PrefixTrieTests {

        @Test
        @DisplayName("Test 1.1: Exact subnet match returns configured PolicyAction")
        void testExactSubnetMatch() {
            BitwisePrefixTrie trie = new BitwisePrefixTrie();
            trie.insertCidr("10.0.5.0/24", PolicyAction.HONEYPOT_TRAP);

            BitwisePrefixTrie.PolicyMatch match = trie.longestPrefixMatch("10.0.5.42");
            assertEquals(PolicyAction.HONEYPOT_TRAP, match.action());
            assertEquals("10.0.5.0/24", match.matchedCidr());
        }

        @Test
        @DisplayName("Test 1.2: Longest Prefix Match (LPM) resolves overlapping /16 vs /24 subnets")
        void testLongestPrefixOverlap() {
            BitwisePrefixTrie trie = new BitwisePrefixTrie();
            trie.insertCidr("172.16.0.0/16", PolicyAction.MONITOR_EXTERNAL);
            trie.insertCidr("172.16.99.0/24", PolicyAction.ALLOW_INTERNAL);

            assertEquals(PolicyAction.ALLOW_INTERNAL, trie.longestPrefixMatch("172.16.99.10").action());
            assertEquals(PolicyAction.MONITOR_EXTERNAL, trie.longestPrefixMatch("172.16.50.10").action());
        }

        @Test
        @DisplayName("Test 1.3: Boundary /32 host-specific rule and /0 default fallback")
        void testBoundaryMasks() {
            BitwisePrefixTrie trie = new BitwisePrefixTrie();
            trie.insertCidr("0.0.0.0/0", PolicyAction.MONITOR_EXTERNAL);
            trie.insertCidr("45.33.32.156/32", PolicyAction.BLOCK_KNOWN_MALICIOUS);

            assertEquals(PolicyAction.BLOCK_KNOWN_MALICIOUS, trie.longestPrefixMatch("45.33.32.156").action());
            assertEquals(PolicyAction.MONITOR_EXTERNAL, trie.longestPrefixMatch("45.33.32.157").action());
        }

        @Test
        @DisplayName("Test 1.4: Empty Trie defaults safely to MONITOR_EXTERNAL")
        void testEmptyTrieFallback() {
            BitwisePrefixTrie trie = new BitwisePrefixTrie();
            BitwisePrefixTrie.PolicyMatch match = trie.longestPrefixMatch("8.8.8.8");
            assertEquals(PolicyAction.MONITOR_EXTERNAL, match.action());
        }

        @Test
        @DisplayName("Test 1.5: Edge case rejects malformed IPv4 octets and CIDR masks > 32")
        void testInvalidInputsThrowException() {
            BitwisePrefixTrie trie = new BitwisePrefixTrie();
            assertThrows(IllegalArgumentException.class, () -> trie.insertCidr("192.168.1.0/33", PolicyAction.ALLOW_INTERNAL));
            assertThrows(IllegalArgumentException.class, () -> trie.longestPrefixMatch("999.10.0.1"));
            assertThrows(IllegalArgumentException.class, () -> trie.longestPrefixMatch(""));
        }
    }

    // =========================================================================
    // 2. RED-BLACK TREE TESTS (Unit 3: Self-Balancing Session TTL Tree)
    // =========================================================================
    @Nested
    @DisplayName("2. RedBlackTree Invariant & TTL Eviction Tests")
    class RedBlackTreeTests {

        @Test
        @DisplayName("Test 2.1: Monotonically ascending insertions maintain valid Red-Black height invariants")
        void testAscendingInsertionsBalanceInvariant() {
            RedBlackTree<String> rbt = new RedBlackTree<>();
            for (long ts = 1000L; ts <= 50_000L; ts += 1000L) {
                rbt.insert(ts, "session-" + ts);
            }
            assertEquals(50, rbt.size());
            assertTrue(rbt.isValidRedBlackTree(), "Red-Black invariants violated after sequential insertions");
        }

        @Test
        @DisplayName("Test 2.2: Range-based TTL eviction purges only expired sessions in chronological order")
        void testEvictExpiredSessions() {
            RedBlackTree<String> rbt = new RedBlackTree<>();
            rbt.insert(5000L, "S3");
            rbt.insert(1000L, "S1");
            rbt.insert(3000L, "S2");
            rbt.insert(9000L, "S4");

            List<String> evicted = rbt.evictExpired(3000L);
            assertEquals(List.of("S1", "S2"), evicted);
            assertEquals(2, rbt.size());
            assertTrue(rbt.isValidRedBlackTree());
        }

        @Test
        @DisplayName("Test 2.3: Duplicate expiration timestamps are preserved without overwriting")
        void testDuplicateTimestamps() {
            RedBlackTree<String> rbt = new RedBlackTree<>();
            rbt.insert(2000L, "DupA");
            rbt.insert(2000L, "DupB");
            rbt.insert(2000L, "DupC");

            assertEquals(3, rbt.size());
            List<String> evicted = rbt.evictExpired(2000L);
            assertEquals(3, evicted.size());
            assertTrue(rbt.isEmpty());
        }

        @Test
        @DisplayName("Test 2.4: Boundary eviction when currentTime is earlier than all active sessions")
        void testNoExpiredSessionsBoundary() {
            RedBlackTree<String> rbt = new RedBlackTree<>();
            rbt.insert(10_000L, "FutureSession");
            List<String> evicted = rbt.evictExpired(5_000L);

            assertTrue(evicted.isEmpty());
            assertEquals(1, rbt.size());
        }

        @Test
        @DisplayName("Test 2.5: Edge case eviction on empty tree returns empty list without error")
        void testEmptyTreeEviction() {
            RedBlackTree<String> rbt = new RedBlackTree<>();
            assertTrue(rbt.evictExpired(999_999L).isEmpty());
            assertTrue(rbt.isValidRedBlackTree());
        }
    }

    // =========================================================================
    // 3. SEGMENT TREE TESTS (Unit 3: Sliding Time-Window Range Queries)
    // =========================================================================
    @Nested
    @DisplayName("3. SegmentTree Range Query & Boundary Tests")
    class SegmentTreeTests {

        @Test
        @DisplayName("Test 3.1: Point updates accurately accumulate into range-sum queries")
        void testPointUpdatesAndRangeSum() {
            SegmentTree st = new SegmentTree(8);
            st.update(1, 5);
            st.update(3, 10);
            st.update(4, 7);
            st.update(7, 20);

            assertEquals(22L, st.queryRangeSum(1, 5));
            assertEquals(42L, st.queryRangeSum(0, 7));
        }

        @Test
        @DisplayName("Test 3.2: Range-max query isolates peak burst bucket within sub-window")
        void testRangeMaxPeakDetection() {
            SegmentTree st = new SegmentTree(6);
            st.update(0, 4);
            st.update(2, 35); // Burst spike
            st.update(3, 12);
            st.update(5, 50); // Outside sub-window [0..4]

            assertEquals(35L, st.queryRangeMax(0, 4));
            assertEquals(50L, st.queryRangeMax(0, 5));
        }

        @Test
        @DisplayName("Test 3.3: Boundary single-bucket query [i, i] returns exact bucket value")
        void testSingleBucketBoundaryQuery() {
            SegmentTree st = new SegmentTree(5);
            st.update(2, 18);

            assertEquals(18L, st.queryRangeSum(2, 2));
            assertEquals(18L, st.queryRangeMax(2, 2));
        }

        @Test
        @DisplayName("Test 3.4: Multiple incremental updates on same bucket accumulate properly")
        void testCumulativeBucketUpdates() {
            SegmentTree st = new SegmentTree(4);
            st.update(0, 3);
            st.update(0, 7);
            st.update(0, 5);

            assertEquals(15L, st.queryRangeSum(0, 0));
        }

        @Test
        @DisplayName("Test 3.5: Edge cases reject inverted [left > right] or out-of-bounds indices")
        void testInvalidRangesAndIndices() {
            SegmentTree st = new SegmentTree(5);
            assertThrows(IllegalArgumentException.class, () -> st.queryRangeSum(4, 2));
            assertThrows(IllegalArgumentException.class, () -> st.queryRangeMax(-1, 3));
            assertThrows(IndexOutOfBoundsException.class, () -> st.update(5, 1));
        }
    }

    // =========================================================================
    // 4. RANDOMIZED QUICKSELECT TESTS (Unit 1 & Unit 6 / CO5: Top-K Selection)
    // =========================================================================
    @Nested
    @DisplayName("4. RandomizedQuickselect (CO5) Correctness & Edge Tests")
    class RandomizedQuickselectTests {

        private SourceRiskScore makeSource(String ip, int ports) {
            return new SourceRiskScore(ip, ports, 1, 0, ports, PolicyAction.MONITOR_EXTERNAL);
        }

        @Test
        @DisplayName("Test 4.1: Extracts exact Top-K highest risk scanners in descending order")
        void testTopKExtraction() {
            RandomizedQuickselect qs = new RandomizedQuickselect(123L);
            List<SourceRiskScore> list = List.of(
                makeSource("1.1.1.1", 5),
                makeSource("2.2.2.2", 50),
                makeSource("3.3.3.3", 12),
                makeSource("4.4.4.4", 90),
                makeSource("5.5.5.5", 30)
            );

            List<SourceRiskScore> top3 = qs.selectTopK(list, 3);
            assertEquals(3, top3.size());
            assertEquals("4.4.4.4", top3.get(0).getSrcIp());
            assertEquals("2.2.2.2", top3.get(1).getSrcIp());
            assertEquals("5.5.5.5", top3.get(2).getSrcIp());
        }

        @Test
        @DisplayName("Test 4.2: Boundary K = 1 returns the single highest-risk attacker")
        void testTopOneBoundary() {
            RandomizedQuickselect qs = new RandomizedQuickselect(99L);
            List<SourceRiskScore> list = List.of(
                makeSource("10.1.1.1", 2),
                makeSource("10.1.1.2", 100),
                makeSource("10.1.1.3", 45)
            );

            List<SourceRiskScore> top1 = qs.selectTopK(list, 1);
            assertEquals(1, top1.size());
            assertEquals("10.1.1.2", top1.get(0).getSrcIp());
        }

        @Test
        @DisplayName("Test 4.3: Boundary K > N safely caps output to N elements without out-of-bounds")
        void testKExceedsListSize() {
            RandomizedQuickselect qs = new RandomizedQuickselect(7L);
            List<SourceRiskScore> list = List.of(
                makeSource("10.0.0.1", 10),
                makeSource("10.0.0.2", 20)
            );

            List<SourceRiskScore> result = qs.selectTopK(list, 10);
            assertEquals(2, result.size());
            assertEquals("10.0.0.2", result.get(0).getSrcIp());
        }

        @Test
        @DisplayName("Test 4.4: Adversarial all-duplicate scores partition cleanly without infinite loop")
        void testAllIdenticalScores() {
            RandomizedQuickselect qs = new RandomizedQuickselect(42L);
            List<SourceRiskScore> list = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                list.add(makeSource("198.51.100." + i, 15));
            }

            List<SourceRiskScore> top5 = qs.selectTopK(list, 5);
            assertEquals(5, top5.size());
        }

        @Test
        @DisplayName("Test 4.5: Edge cases handle empty input list and reject K <= 0")
        void testEmptyAndInvalidK() {
            RandomizedQuickselect qs = new RandomizedQuickselect();
            assertTrue(qs.selectTopK(List.of(), 5).isEmpty());
            assertThrows(IllegalArgumentException.class, () ->
                qs.selectTopK(List.of(makeSource("1.1.1.1", 10)), 0)
            );
        }
    }
}