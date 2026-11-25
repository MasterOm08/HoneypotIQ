package com.honeypotiq.algorithms;

/**
 * Custom Segment Tree supporting O(log M) point updates and O(log M) range sum & range max
 * queries over discrete time buckets to detect port-scan bursts.
 * Syllabus Unit 3: Range Queries / Segment Trees.
 */
public class SegmentTree {

    private final int numBuckets;
    private final long[] sumTree;
    private final long[] maxTree;

    public SegmentTree(int numBuckets) {
        if (numBuckets <= 0) {
            throw new IllegalArgumentException("Number of time buckets must be positive");
        }
        this.numBuckets = numBuckets;
        this.sumTree = new long[4 * numBuckets];
        this.maxTree = new long[4 * numBuckets];
    }

    /**
     * Increments the scan intensity count at bucketIndex by delta.
     * Time Complexity: O(log M).
     */
    public void update(int bucketIndex, long delta) {
        if (bucketIndex < 0 || bucketIndex >= numBuckets) {
            throw new IndexOutOfBoundsException("Bucket index out of bounds: " + bucketIndex);
        }
        updateRecursive(1, 0, numBuckets - 1, bucketIndex, delta);
    }

    private void updateRecursive(int node, int start, int end, int idx, long delta) {
        if (start == end) {
            sumTree[node] += delta;
            maxTree[node] += delta;
            return;
        }
        int mid = start + (end - start) / 2;
        if (idx <= mid) {
            updateRecursive(2 * node, start, mid, idx, delta);
        } else {
            updateRecursive(2 * node + 1, mid + 1, end, idx, delta);
        }
        sumTree[node] = sumTree[2 * node] + sumTree[2 * node + 1];
        maxTree[node] = Math.max(maxTree[2 * node], maxTree[2 * node + 1]);
    }

    /**
     * Queries total connection intensity over inclusive bucket range [left, right].
     * Time Complexity: O(log M).
     */
    public long queryRangeSum(int left, int right) {
        validateRange(left, right);
        return querySumRecursive(1, 0, numBuckets - 1, left, right);
    }

    private long querySumRecursive(int node, int start, int end, int l, int r) {
        if (r < start || end < l) {
            return 0L;
        }
        if (l <= start && end <= r) {
            return sumTree[node];
        }
        int mid = start + (end - start) / 2;
        return querySumRecursive(2 * node, start, mid, l, r)
             + querySumRecursive(2 * node + 1, mid + 1, end, l, r);
    }

    /**
     * Queries peak single-bucket spike intensity over inclusive bucket range [left, right].
     * Time Complexity: O(log M).
     */
    public long queryRangeMax(int left, int right) {
        validateRange(left, right);
        return queryMaxRecursive(1, 0, numBuckets - 1, left, right);
    }

    private long queryMaxRecursive(int node, int start, int end, int l, int r) {
        if (r < start || end < l) {
            return 0L;
        }
        if (l <= start && end <= r) {
            return maxTree[node];
        }
        int mid = start + (end - start) / 2;
        return Math.max(
            queryMaxRecursive(2 * node, start, mid, l, r),
            queryMaxRecursive(2 * node + 1, mid + 1, end, l, r)
        );
    }

    private void validateRange(int left, int right) {
        if (left < 0 || right >= numBuckets || left > right) {
            throw new IllegalArgumentException(
                String.format("Invalid query range [%d, %d] for %d buckets", left, right, numBuckets)
            );
        }
    }

    public int getNumBuckets() {
        return numBuckets;
    }
}