package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.*;

import java.util.Arrays;
import java.util.Random;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EncryptTests {

    private final RabbitCipher cipher = ServiceLoader.load(RabbitCipher.class).findFirst().orElseThrow();

    private static final String EXP_ZERO_KEY_STATE = "6E9E1D18 F5A54E5C F8FD49C6 9B94253F DCD14A79 1F32FA20 D2055921 53F371D0 E802074F 5206296D 01486DF2 67203CE4 23AACE55 26E87A8F CC2E04F2 D6A0F672 1";

    @BeforeAll
    void checkCanInit() {
        // Check state can initialise
        cipher.initialiseCipher(new byte[16]);
        String cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(EXP_ZERO_KEY_STATE, cipherState);
    }

    @Test
    @Order(0)
    void encryptSingleBlockTest() {
        cipher.initialiseCipher(new byte[] { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 });
        cipher.initialiseIV(new byte[] { (byte)0xFF, (byte)0xFE,(byte)0xFD,(byte)0xFC,(byte)0xFB,(byte)0xFA,(byte)0xEF,(byte)0xEE });

        byte[] plaintext = new byte[] { -93, 1, -26, -4, -64, 2, -23, 122, -44, -72, 8, 9, 31, 100, -80, 115 };
        byte[] expectedBlock = { 65, -60, 51, -40, -15, -72, -66, 55, -75, -62, -12, -40, 102, 19, 63, -58 };
        byte[] encryptedBlock = Arrays.copyOf(plaintext,plaintext.length);
        cipher.encrypt(encryptedBlock);

        assertArrayEquals(expectedBlock, encryptedBlock);
    }

    @Test
    @Order(1)
    void encryptMultipleBlockTest() {
        cipher.initialiseCipher(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });
        cipher.initialiseIV(new byte[] { (byte)0xFF, (byte)0xFE, (byte)0xFD, (byte)0xFC, (byte)0xFB, (byte)0xFA, (byte)0xEF, (byte)0xEE });

        byte[] plaintext = new byte[] { -93, 1, -26, -4, -64, 2, -23, 122, -44, -72, 8, 9, 31, 100, -80, 115 };
        byte[] expectedBlock = { -118, 44, -13, 62, -14, 101, 39, -5, -50, -39, -19, 68, 40, -50, -34, 88 };
        byte[] encryptedBlock = Arrays.copyOf(plaintext,plaintext.length);

        for (int i = 0; i < 10; i++) {
            cipher.encrypt(encryptedBlock);
        }
        assertArrayEquals(expectedBlock, encryptedBlock);
    }

    @Test
    @Order(2)
    void decryptSingleBlockTest() {
        cipher.initialiseCipher(new byte[] { 1, 5, 8, 2, 0, 9, 3, 6, 3, 7, 8, 2, 6, 2, 9, 0 });
        cipher.initialiseIV(new byte[] { (byte)0xFF, (byte)0xFE, (byte)0xFD, (byte)0xFC, (byte)0xFB, (byte)0xFA, (byte)0xEF, (byte)0xEE });

        byte[] ciphertext = { 65, -60, 51, -40, -15, -72, -66, 55, -75, -62, -12, -40, 102, 19, 63, -58 };

        byte[] expectedBlock = new byte[] { 55, -7, 125, -12, -88, -117, 1, -15, -95, -34, 95, 84, -60, -8, -97, -44 };
        byte[] decryptedBlock = Arrays.copyOf(ciphertext, ciphertext.length);
        cipher.decrypt(decryptedBlock);

        assertArrayEquals(expectedBlock, decryptedBlock);
    }

    @Test
    @Order(3)
    void decryptMultipleBlockTest() {
        cipher.initialiseCipher(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });
        cipher.initialiseIV(new byte[] { (byte)0xFF, (byte)0xFE, (byte)0xFD, (byte)0xFC, (byte)0xFB, (byte)0xFA, (byte)0xEF, (byte)0xEE });

        byte[] ciphertext = { -96, 31, -10, 61, 7, -39, -86, 65, -82, -20, -27, 113, 61, -56, 108, -61 };
        byte[] expectedBlock = new byte[] { -119, 50, -29, -1, 53, -66, 100, -64, -76, -115, 0, 60, 10, 98, 2, -24 };
        byte[] decryptedBlock = Arrays.copyOf(ciphertext, ciphertext.length);

        for (int i = 0; i < 10; i++) {
            cipher.encrypt(decryptedBlock);
        }
        assertArrayEquals(expectedBlock, decryptedBlock);
    }

    @Test
    @Order(3)
    void extendedRandomEncryptDecryptBlockTests() {
        for (int i = 0; i < 10; i++) {
            byte[] key = getRandomKey();
            byte[] iv = getRandomIV();

            byte[] plaintext = getRandomBlock();
            byte[] ciphertext = Arrays.copyOf(plaintext, plaintext.length);

            cipher.initialiseCipher(key);
            cipher.initialiseIV(iv);

            // Encrypt 3 times with successive blocks
            for (int j = 0; j < 3; j++) {
                cipher.encrypt(ciphertext);
                // Ensures some encryption has occurred. Chances of this test raising a false
                // negative is 3/2^128
                assertFalse(Arrays.equals(plaintext, ciphertext));
            }

            // Decrypt again
            cipher.initialiseIV(iv);
            for (int j = 0; j < 3; j++) {
                cipher.decrypt(ciphertext);
            }

            assertArrayEquals(plaintext, ciphertext);
        }
    }

    static final Random rand = new Random();

    static byte[] getRandomKey() {
        byte[] key = new byte[16];
        rand.nextBytes(key);
        return key;
    }

    static byte[] getRandomIV() {
        byte[] iv = new byte[8];
        rand.nextBytes(iv);
        return iv;
    }

    static byte[] getRandomBlock() {
        byte[] bl = new byte[16];
        rand.nextBytes(bl);
        return bl;
    }

}
