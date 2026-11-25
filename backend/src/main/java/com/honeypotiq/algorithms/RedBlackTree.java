package com.honeypotiq.algorithms;

import java.util.ArrayList;
import java.util.List;

/**
 * Custom Red-Black Tree keyed by expiration timestamp (ms) to manage active network sessions
 * and evict stale records in O(log N) amortized time per record.
 * Syllabus Unit 3: Balanced Search Trees.
 */
public class RedBlackTree<T> {

    private static final boolean RED = true;
    private static final boolean BLACK = false;

    private class Node {
        long expiryTimestamp;
        T payload;
        Node left, right, parent;
        boolean color;

        Node(long expiryTimestamp, T payload, boolean color) {
            this.expiryTimestamp = expiryTimestamp;
            this.payload = payload;
            this.color = color;
        }
    }

    private Node root;
    private int size;

    public RedBlackTree() {
        this.root = null;
        this.size = 0;
    }

    public int size() {
        return size;
    }

    public boolean isEmpty() {
        return size == 0;
    }

    /**
     * Inserts a session record ordered by expiryTimestamp.
     * Supports duplicate timestamps by placing equal keys in the right subtree.
     * Time Complexity: O(log N).
     */
    public void insert(long expiryTimestamp, T payload) {
        Node newNode = new Node(expiryTimestamp, payload, RED);
        if (root == null) {
            root = newNode;
            root.color = BLACK;
            size++;
            return;
        }

        Node curr = root;
        Node parent = null;
        while (curr != null) {
            parent = curr;
            if (expiryTimestamp < curr.expiryTimestamp) {
                curr = curr.left;
            } else {
                curr = curr.right;
            }
        }

        newNode.parent = parent;
        if (expiryTimestamp < parent.expiryTimestamp) {
            parent.left = newNode;
        } else {
            parent.right = newNode;
        }

        size++;
        fixInsert(newNode);
    }

    /**
     * Evicts and returns all records with expiryTimestamp <= currentTimeMs.
     * Time Complexity: O(K log N) where K is the number of expired entries.
     */
    public List<T> evictExpired(long currentTimeMs) {
        List<T> expired = new ArrayList<>();
        while (root != null) {
            Node minNode = minimum(root);
            if (minNode.expiryTimestamp <= currentTimeMs) {
                expired.add(minNode.payload);
                deleteNode(minNode);
            } else {
                break;
            }
        }
        return expired;
    }

    /**
     * Verifies Red-Black Tree invariants (used in unit tests for correctness proof).
     */
    public boolean isValidRedBlackTree() {
        if (root == null) return true;
        if (root.color != BLACK) return false;
        return checkBlackHeight(root) != -1;
    }

    private int checkBlackHeight(Node node) {
        if (node == null) return 1;
        if (node.color == RED) {
            if ((node.left != null && node.left.color == RED) ||
                (node.right != null && node.right.color == RED)) {
                return -1; // Red-Red violation
            }
        }
        int leftHeight = checkBlackHeight(node.left);
        int rightHeight = checkBlackHeight(node.right);
        if (leftHeight == -1 || rightHeight == -1 || leftHeight != rightHeight) {
            return -1; // Black-height mismatch
        }
        return leftHeight + (node.color == BLACK ? 1 : 0);
    }

    private void fixInsert(Node z) {
        while (z.parent != null && z.parent.color == RED) {
            Node grandParent = z.parent.parent;
            if (grandParent == null) break;

            if (z.parent == grandParent.left) {
                Node uncle = grandParent.right;
                if (uncle != null && uncle.color == RED) {
                    z.parent.color = BLACK;
                    uncle.color = BLACK;
                    grandParent.color = RED;
                    z = grandParent;
                } else {
                    if (z == z.parent.right) {
                        z = z.parent;
                        rotateLeft(z);
                    }
                    z.parent.color = BLACK;
                    grandParent.color = RED;
                    rotateRight(grandParent);
                }
            } else {
                Node uncle = grandParent.left;
                if (uncle != null && uncle.color == RED) {
                    z.parent.color = BLACK;
                    uncle.color = BLACK;
                    grandParent.color = RED;
                    z = grandParent;
                } else {
                    if (z == z.parent.left) {
                        z = z.parent;
                        rotateRight(z);
                    }
                    z.parent.color = BLACK;
                    grandParent.color = RED;
                    rotateLeft(grandParent);
                }
            }
        }
        root.color = BLACK;
    }

    private void deleteNode(Node z) {
        Node y = z;
        Node x;
        Node xParent;
        boolean yOriginalColor = y.color;

        if (z.left == null) {
            x = z.right;
            xParent = z.parent;
            transplant(z, z.right);
        } else if (z.right == null) {
            x = z.left;
            xParent = z.parent;
            transplant(z, z.left);
        } else {
            y = minimum(z.right);
            yOriginalColor = y.color;
            x = y.right;
            if (y.parent == z) {
                xParent = y;
            } else {
                xParent = y.parent;
                transplant(y, y.right);
                y.right = z.right;
                y.right.parent = y;
            }
            transplant(z, y);
            y.left = z.left;
            y.left.parent = y;
            y.color = z.color;
        }

        size--;
        if (yOriginalColor == BLACK) {
            fixDelete(x, xParent);
        }
    }

    private void fixDelete(Node x, Node xParent) {
        while (x != root && (x == null || x.color == BLACK)) {
            if (xParent == null) break;
            if (x == xParent.left) {
                Node w = xParent.right;
                if (w != null && w.color == RED) {
                    w.color = BLACK;
                    xParent.color = RED;
                    rotateLeft(xParent);
                    w = xParent.right;
                }
                if (w == null) {
                    x = xParent;
                    xParent = x.parent;
                } else if ((w.left == null || w.left.color == BLACK) &&
                           (w.right == null || w.right.color == BLACK)) {
                    w.color = RED;
                    x = xParent;
                    xParent = x.parent;
                } else {
                    if (w.right == null || w.right.color == BLACK) {
                        if (w.left != null) w.left.color = BLACK;
                        w.color = RED;
                        rotateRight(w);
                        w = xParent.right;
                    }
                    if (w != null) {
                        w.color = xParent.color;
                        if (w.right != null) w.right.color = BLACK;
                    }
                    xParent.color = BLACK;
                    rotateLeft(xParent);
                    x = root;
                }
            } else {
                Node w = xParent.left;
                if (w != null && w.color == RED) {
                    w.color = BLACK;
                    xParent.color = RED;
                    rotateRight(xParent);
                    w = xParent.left;
                }
                if (w == null) {
                    x = xParent;
                    xParent = x.parent;
                } else if ((w.right == null || w.right.color == BLACK) &&
                           (w.left == null || w.left.color == BLACK)) {
                    w.color = RED;
                    x = xParent;
                    xParent = x.parent;
                } else {
                    if (w.left == null || w.left.color == BLACK) {
                        if (w.right != null) w.right.color = BLACK;
                        w.color = RED;
                        rotateLeft(w);
                        w = xParent.left;
                    }
                    if (w != null) {
                        w.color = xParent.color;
                        if (w.left != null) w.left.color = BLACK;
                    }
                    xParent.color = BLACK;
                    rotateRight(xParent);
                    x = root;
                }
            }
        }
        if (x != null) x.color = BLACK;
    }

    private void transplant(Node u, Node v) {
        if (u.parent == null) {
            root = v;
        } else if (u == u.parent.left) {
            u.parent.left = v;
        } else {
            u.parent.right = v;
        }
        if (v != null) {
            v.parent = u.parent;
        }
    }

    private Node minimum(Node node) {
        while (node.left != null) {
            node = node.left;
        }
        return node;
    }

    private void rotateLeft(Node x) {
        Node y = x.right;
        x.right = y.left;
        if (y.left != null) y.left.parent = x;
        y.parent = x.parent;
        if (x.parent == null) root = y;
        else if (x == x.parent.left) x.parent.left = y;
        else x.parent.right = y;
        y.left = x;
        x.parent = y;
    }

    private void rotateRight(Node y) {
        Node x = y.left;
        y.left = x.right;
        if (x.right != null) x.right.parent = y;
        x.parent = y.parent;
        if (y.parent == null) root = x;
        else if (y == y.parent.right) y.parent.right = x;
        else y.parent.left = x;
        x.right = y;
        y.parent = x;
    }
}