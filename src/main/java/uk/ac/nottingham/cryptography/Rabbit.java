package uk.ac.nottingham.cryptography;

public class Rabbit implements RabbitCipher {

    // The working state of the cipher.
    private RabbitState mainState;

    // The master state that the cipher is reset to when initialising the IV.
    private RabbitState masterState;

    // The 128 bit output buffer.
    private byte[] bufferS = new byte[16];

    private final long WORDSIZE = 0x100000000L;
    private final int INTBYTEMASK = 0xFF;
    private final long LONG32MASK = 0xFFFFFFFFL;

    /**
     * Splits the input key into an array of 8 subkeys.
     * Each subkey is represented by an integer containing 16 bits of the original key.
     * The key is divided into subkeys K0 = K[15..0], K1 = K[31..16], ... K7 = K[127..112].
     *
     * @param key The byte array representing the encryption key.
     * @return An array of 8 integers, each representing a subkey.
     */
    private int[] splitIntoSubkeys(byte[] key) {
        int[] subkeys = new int[8];

        for (int i = 0; i < 8; i++) {
            // Extract the first and second halves of the subkey from the original key
            // and combine them together into one 16 bit subkey.
            subkeys[i] = (key[(i * 2) + 1] & INTBYTEMASK) << 8 | key[(i * 2)] & INTBYTEMASK;
        }

        return subkeys;
    }

    /*
    private int combinedKeyBytes(byte[] key, int a, int b) {
        // Would prefer to use something like this to be
        // able to use key directly instead of using subkeys.
        return ((key[a] & BYTEMASK) << 8) | key[b] & BYTEMASK;
    }
    */


    /**
     * Initialises the cipher with a provided key.
     * The key is used to set up the internal state of the cipher for encryption or decryption.
     * This method expects a key of length 16 bytes.
     *
     * @param key The byte array representing the encryption key.
     */
    @Override
    public void initialiseCipher(byte[] key) {
        // Throw error if the length of key is not 16.
        if (key.length != 16) {
            throw new IllegalArgumentException("Key length not right, has to be 16");
        }

        // Reset the main and master states.
        mainState = new RabbitState();
        masterState = new RabbitState();

        // Split the input key into subkeys.
        int[] subkeys = splitIntoSubkeys(key);

        // Initialise mainState using subkeys
        for (int i = 0; i < 8; i++) {
            if (i % 2 == 0) {
                mainState.X[i] = (subkeys[(i + 1) % 8] << 16) | subkeys[(i + 0) % 8];
                mainState.C[i] = (subkeys[(i + 4) % 8] << 16) | subkeys[(i + 5) % 8];
            } else {
                mainState.X[i] = (subkeys[(i + 5) % 8] << 16) | subkeys[(i + 4) % 8];
                mainState.C[i] = (subkeys[(i + 0) % 8] << 16) | subkeys[(i + 1) % 8];
            }
        }

        // Iterate the system 4 times.
        rounds(4);

        // Finalise mainState.
        for (int i = 0; i < 8; i++) {
            mainState.C[i] = mainState.C[i] ^ mainState.X[(i + 4) % 8];
        }

        // Copy the main state into the master state.
        masterState.copyState(mainState);
    }

    /**
     * This function allows the initialiseIV to work directly on the IV
     * instead of having to create an array of smaller sections of the
     * iv before then combining them both.
     *
     * @param cValue is the value of the array C to be XOR'd.
     * @param iv The byte array representing the initialisation vector (IV).
     * @param a Value of IV to be shifted 24 bits.
     * @param b Value of IV to be shifted 16 bits.
     * @param c Value of IV to be shifted 8 bits.
     * @param d Value of IV.
     * @return The integer result of the XOR.
     */
    private int xorIV(int cValue, byte[] iv, int a, int b, int c, int d) {
        return cValue ^ (((iv[a] & INTBYTEMASK) << 24) | ((iv[b] & INTBYTEMASK) << 16) |
                         ((iv[c] & INTBYTEMASK) << 8)  | (iv[d] & INTBYTEMASK));
    }

    /**
     * The IV setup scheme with a provided initialisation vector (IV).
     * When IV is added, the state is reset to the master state.
     * This method expects an IV of length 8 bytes.
     *
     * @param iv The byte array representing the initialisation vector (IV).
     */
    @Override
    public void initialiseIV(byte[] iv) {
        // Do nothing if the IV it is either null or not of length 8.
        if (iv == null || iv.length != 8) {
            return;
        }

        // Reset the main state to a copy of the master state.
        mainState.copyState(masterState);

        // XOR each C[i] with the corresponding part of the IV.
        mainState.C[0] = xorIV(mainState.C[0], iv, 3, 2, 1, 0);
        mainState.C[1] = xorIV(mainState.C[1], iv, 7, 6, 3, 2);
        mainState.C[2] = xorIV(mainState.C[2], iv, 7, 6, 5, 4);
        mainState.C[3] = xorIV(mainState.C[3], iv, 5, 4, 1, 0);
        mainState.C[4] = xorIV(mainState.C[4], iv, 3, 2, 1, 0);
        mainState.C[5] = xorIV(mainState.C[5], iv, 7, 6, 3, 2);
        mainState.C[6] = xorIV(mainState.C[6], iv, 7, 6, 5, 4);
        mainState.C[7] = xorIV(mainState.C[7], iv, 5, 4, 1, 0);

        // Iterate the system 4 times.
        rounds(4);
    }

    /**
     * This function updates the internal counter state. This function does
     * not affect the internal X state.
     *
     * In each iteration of the update, the corresponding constant from the
     * pre-defined array A is added to the current counter, along with the
     * carry bit from the previous iteration. The resulting sum is split into
     * the updated counter and carry bit b for the next iteration.
     */
    @Override
    public final void counterUpdate() {
        // Pre-defined constants from RFC 4503, Section 2.5.
        int[] A = {
                0x4D34D34D, 0xD34D34D3,
                0x34D34D34, 0x4D34D34D,
                0xD34D34D3, 0x34D34D34,
                0x4D34D34D, 0xD34D34D3
        };

        // Iterating over the 8 counter elements.
        for (int i = 0; i < 8; i++) {
            // Calculate the sum of the current counter, the constant from A,
            // and the carry bit from the previous iteration.
            // Using masking for modular addition.
            long temp = ((long) mainState.C[i] & LONG32MASK) +
                        ((long) A[i] & LONG32MASK) +
                        ((long) mainState.b & LONG32MASK);

            // Updating b with temp div WORDSIZE.
            mainState.b = (int) (temp >>> 32);

            // Updating Ci with temp mod WORDSIZE.
            mainState.C[i] = (int) temp;
        }
    }

    /**
     * The g function transforms two 32 bit numbers into one
     * 32 bit output.
     *
     * @param u One 32 bit input.
     * @param v One 32 bit input.
     * @return The 32 bit integer output.
     */
    private int g(int u, int v) {
        // Modular addition of U and V.
        long UV = ((long) u + v) & LONG32MASK;
        // Square of UV.
        long squareUV = UV * UV;
        // Return the LSW xor MSW
        return ((int) squareUV) ^ ((int) (squareUV >>> 32));
    }

    /**
     * Just a wrapper for the built-in rotate function.
     */
    public static int rl(int i, int distance) {
        return Integer.rotateLeft(i, distance);
    }

    /**
     * Computes the next internal state.
     *
     * Updates the cipher's internal state X based on a set of intermediate
     * values G. Each value Gi is calculated from the g function with
     * corresponding elements from the current state X and the counter C.
     * The new state X is then updated using the G values and left rotations.
     */
    @Override
    public final void nextState() {
        int[] G = new int[8];

        // Calculate G using the g function.
        for (int i = 0; i < 8; i++) {
            G[i] = g(mainState.X[i], mainState.C[i]);
        }

        // Update the cipher's internal state x using the G values
        // and left rotations, using pre-defined values.
        mainState.X[0] = G[0] + rl(G[7], 16) + rl(G[6], 16);
        mainState.X[1] = G[1] + rl(G[0], 8) + G[7];
        mainState.X[2] = G[2] + rl(G[1], 16) + rl(G[0], 16);
        mainState.X[3] = G[3] + rl(G[2], 8) + G[1];
        mainState.X[4] = G[4] + rl(G[3], 16) + rl(G[2], 16);
        mainState.X[5] = G[5] + rl(G[4], 8) + G[3];
        mainState.X[6] = G[6] + rl(G[5], 16) + rl(G[4], 16);
        mainState.X[7] = G[7] + rl(G[6], 8) + G[5];
    }

    /**
     * Iterates through counterUpdate and nextState.
     * Also extracts bytes to buffer.
     *
     * @param n The number of iterations.
     */
    private void rounds(int n) {
        for (int i = 0; i < n; i++) {
            counterUpdate();
            nextState();
            bufferS = extraction();
        }
    }

    /**
     * Returns the first half of bits in an int.
     *
     * @param x The input integer.
     * @return The output integer containing the first half.
     */
    private int fh(int x) {
        return (x & 0xFFFF0000) >> 16;
    }

    /**
     * Returns the last half of bits in an int.
     *
     * @param x The input integer.
     * @return The output integer containing the last half.
     */
    private int lh(int x) {
        return x & 0x0000FFFF;
    }



    /**
     * Extracts a 16-byte output block from the current internal state.
     * The extraction function uses the least and most significant halves of
     * selected state elements to generate a 16-byte output array.
     *
     * I ran tests to see whether assigning the values straight into the output
     * block would be more efficient, but they both took a similar amount of
     * time (within 2%). I stuck with the temp array as it is easier to read.
     *
     * @return A 16-byte output block extracted from the current internal state.
     */
    private byte[] extraction() {
        int[] temp = new int[16];
        byte[] output = new byte[16];

        // Calculate values based on the current internal
        // state, assigning them to a temp int array.
        temp[0] = lh(mainState.X[0]) ^ fh(mainState.X[5]);
        temp[1] = fh(mainState.X[0]) ^ lh(mainState.X[3]);
        temp[2] = lh(mainState.X[2]) ^ fh(mainState.X[7]);
        temp[3] = fh(mainState.X[2]) ^ lh(mainState.X[5]);
        temp[4] = lh(mainState.X[4]) ^ fh(mainState.X[1]);
        temp[5] = fh(mainState.X[4]) ^ lh(mainState.X[7]);
        temp[6] = lh(mainState.X[6]) ^ fh(mainState.X[3]);
        temp[7] = fh(mainState.X[6]) ^ lh(mainState.X[1]);

        // Populate the output byte array based on the temp values
        for (int i = 0; i < 8; i++) {
            output[i * 2] = (byte)(temp[i]);
            output[i * 2 + 1] = (byte)(temp[i] >> 8);
        }

        return output;
    }

    /**
     * Encrypts the input byte array (block) using the Rabbit cipher.
     * The block must be 128 bits (16 bytes) or smaller in size.
     * If the block is smaller than 16 bytes, then it will just
     * encrypt the blocks given.
     *
     * @param block The byte array to be encrypted. Must not exceed 128 bits (16 bytes).
     */
    @Override
    public void encrypt(byte[] block) {
        if (block.length > 16) {
            throw new IllegalArgumentException("block to encrypt larger than 16 bytes");
        }

        // Perform one round of the cipher to generate the buffer of bytes
        rounds(1);

        // XOR each byte of the input block with the corresponding byte from the bufferS
        for (int i = 0; i < block.length; i++) {
            block[i] ^= bufferS[i];
        }
    }

    /**
     * Encrypts the given message given IV.
     *
     * This function iterates through each block of the message
     * and encrypts that block in place.
     * It does not matter if the message is not a multiple of 128 bits,
     * as this is a stream cipher, and it just encrypts the bytes given.
     *
     * @param iv       The initialisation vector.
     * @param message  The message to be encrypted in place.
     */
    @Override
    public void encryptMessage(byte[] iv, byte[] message) {
        int blockSize = 16;
        int messageLength = message.length;
        int currentBlockLength;
        byte[] block;

        // Initialises the cipher with the IV.
        initialiseIV(iv);

        // Iterate through the message in blocks of 16 bytes
        for (int i = 0; i < messageLength; i += blockSize) {
            // Calculate the length of the current block
            currentBlockLength = Math.min(blockSize, messageLength - i);

            // Copy the current block in the message, to
            // a new block array which will be encrypted.
            block = new byte[currentBlockLength];
            for (int j = 0; j < currentBlockLength; j++) {
                block[j] = message[i + j];
            }

            // Encrypt the block.
            encrypt(block);

            // Replace the original block in the message with
            // the encrypted block in place.
            for (int j = 0; j < currentBlockLength; j++) {
                message[i + j] = block[j];
            }
        }
    }

    /**
     * As this is a stream cipher, decryption is the same as encryption.
     */
    @Override
    public void decrypt(byte[] block) {
        encrypt(block);
    }

    /**
     * As this is a stream cipher, decryption is the same as encryption.
     */
    @Override
    public void decryptMessage(byte[] iv, byte[] message) {
        encryptMessage(iv, message);
    }

    @Override
    public String getStateString(StringOutputFormatting formatting) {
    	String str = "";
        switch (formatting) {
            case PLAIN:
            	str = String.format("%08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %s", mainState.X[0], mainState.X[1], mainState.X[2], mainState.X[3], mainState.X[4], mainState.X[5], mainState.X[6], mainState.X[7], mainState.C[0], mainState.C[1], mainState.C[2], mainState.C[3], mainState.C[4], mainState.C[5], mainState.C[6], mainState.C[7], mainState.b);
            	break;
            case FANCY:
            	str = String.format("b = %s\nX0 = 0x%08X, X1 = 0x%08X, X2 = 0x%08X, X3 = 0x%08X,\nX4 = 0x%08X, X5 = 0x%08X, X6 = 0x%08X, X7 = 0x%08X,\nC0 = 0x%08X, C1 = 0x%08X, C2 = 0x%08X, C3 = 0x%08X,\nC4 = 0x%08X, C5 = 0x%08X, C6 = 0x%08X, C7 = 0x%08X", mainState.b, mainState.X[0], mainState.X[1], mainState.X[2], mainState.X[3], mainState.X[4], mainState.X[5], mainState.X[6], mainState.X[7], mainState.C[0], mainState.C[1], mainState.C[2], mainState.C[3], mainState.C[4], mainState.C[5], mainState.C[6], mainState.C[7]);
            	break;
        }
        return str;
    }
}
