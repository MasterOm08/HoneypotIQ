package com.honeypotiq.algorithms;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.honeypotiq.model.SourceRiskScore;

/**
 * Custom Randomized Quickselect implementation to extract the Top-K highest-risk
 * source IPs in expected O(N) time without sorting the entire dataset.
 * Syllabus Unit 1 (Selection) & Unit 6 / CO5 (Randomized Algorithms).
 */
public class RandomizedQuickselect {

    private final Random random;

    public RandomizedQuickselect() {
        this.random = new Random();
    }

    // Constructor with fixed seed for deterministic unit testing
    public RandomizedQuickselect(long seed) {
        this.random = new Random(seed);
    }

    /**
     * Selects the Top-K highest risk sources in expected O(N) time.
     * Note: Only the top K elements are ordered at the end so analysts see rank 1..K clearly,
     * while the remaining (N - K) benign sources are never sorted.
     */
    public List<SourceRiskScore> selectTopK(List<SourceRiskScore> sources, int k) {
        if (sources == null || sources.isEmpty()) {
            return new ArrayList<>();
        }
        if (k <= 0) {
            throw new IllegalArgumentException("K must be greater than 0, got: " + k);
        }

        int n = sources.size();
        int effectiveK = Math.min(k, n);
        SourceRiskScore[] arr = sources.toArray(new SourceRiskScore[0]);

        // Partition array so indices [0 .. effectiveK - 1] contain the Top-K highest scores
        quickselect(arr, 0, n - 1, effectiveK - 1);

        // Sort only the tiny Top-K slice (size K << N) for clean rank presentation
        List<SourceRiskScore> topK = new ArrayList<>(effectiveK);
        for (int i = 0; i < effectiveK; i++) {
            topK.add(arr[i]);
        }
        sortTopKSlice(topK);
        return topK;
    }

    private void quickselect(SourceRiskScore[] arr, int left, int right, int targetIndex) {
        while (left < right) {
            // Randomized pivot selection guarantees expected O(N) time and prevents O(N^2) adversarial inputs
            int pivotIndex = left + random.nextInt(right - left + 1);
            int partitionIndex = partitionDescending(arr, left, right, pivotIndex);

            if (partitionIndex == targetIndex) {
                return;
            } else if (targetIndex < partitionIndex) {
                right = partitionIndex - 1;
            } else {
                left = partitionIndex + 1;
            }
        }
    }

    /**
     * Lomuto partition in descending order of riskScore.
     */
    private int partitionDescending(SourceRiskScore[] arr, int left, int right, int pivotIndex) {
        double pivotValue = arr[pivotIndex].getRiskScore();
        swap(arr, pivotIndex, right);
        int storeIndex = left;

        for (int i = left; i < right; i++) {
            if (arr[i].getRiskScore() > pivotValue) {
                swap(arr, storeIndex, i);
                storeIndex++;
            }
        }
        swap(arr, right, storeIndex);
        return storeIndex;
    }

    private void sortTopKSlice(List<SourceRiskScore> list) {
        for (int i = 1; i < list.size(); i++) {
            SourceRiskScore key = list.get(i);
            int j = i - 1;
            while (j >= 0 && list.get(j).getRiskScore() < key.getRiskScore()) {
                list.set(j + 1, list.get(j));
                j--;
            }
            list.set(j + 1, key);
        }
    }

    private void swap(SourceRiskScore[] arr, int i, int j) {
        SourceRiskScore temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}