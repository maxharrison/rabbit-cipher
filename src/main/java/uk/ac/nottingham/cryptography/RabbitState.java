package uk.ac.nottingham.cryptography;

public class RabbitState {
    public int[] X;
    public int[] C;
    public int b;

    public RabbitState() {
        X = new int[8];
        C = new int[8];
        b = 0;
    }

    public void copyState(RabbitState other) {
        System.arraycopy(other.X, 0, this.X, 0, other.X.length);
        System.arraycopy(other.C, 0, this.C, 0, other.C.length);
        this.b = other.b;
    }
}