package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.*;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LongTests {

    private final RabbitCipher cipher = ServiceLoader.load(RabbitCipher.class).findFirst().orElseThrow();

    private static final String EXP_ZERO_KEY_STATE = "6E9E1D18 F5A54E5C F8FD49C6 9B94253F DCD14A79 1F32FA20 D2055921 53F371D0 E802074F 5206296D 01486DF2 67203CE4 23AACE55 26E87A8F CC2E04F2 D6A0F672 1";

    @BeforeAll
    void checkCanInit() {
        // Check state can initialise
        cipher.initialiseCipher(new byte[16]);
        String cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(EXP_ZERO_KEY_STATE, cipherState);

        // Bootstrap to warm up optimiser
        byte[] key = new byte[] { -6, -23, -40, -57, -74, -91, -76, -61, -46, -31, -16, 15, 30, 45, 60, 75 };
        byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 };

        cipher.initialiseCipher(key);
        cipher.initialiseIV(iv);

        byte[] block = new byte[16];
        final int iterations = 10000 / 16 + 1;

        for (int i = 0; i < iterations; i++) {
            cipher.encrypt(block);
        }

        byte[] target = new byte[] { 12, -97, -69, 97, -16, -49, 0, 58, -120, -71, -91, 41, -66, -81, 40, 27 };
        assertArrayEquals(target, block);
    }

    @Test
    @Order(0)
    void long65KBTest() {
        byte[] key = new byte[] { -6, -23, -40, -57, -74, -91, -76, -61, -46, -31, -16, 15, 30, 45, 60, 75 };
        byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 };

        cipher.initialiseCipher(key);
        cipher.initialiseIV(iv);

        byte[] block = new byte[16];
        final int iterations = 65000 / 16 + 1;

        for (int i = 0; i < iterations; i++) {
            cipher.encrypt(block);
        }

        byte[] target = new byte[] { -7, -45, -68, -74, -1, 40, -104, 94, 45, 86, 115, 6, 116, -15, 105, 112 };

        assertArrayEquals(target, block);
    }

    @Test
    @Order(1)
    void long1MBTest() {
        byte[] key = new byte[] { -6, -23, -40, -57, -74, -91, -76, -61, -46, -31, -16, 15, 30, 45, 60, 75 };
        byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 };

        cipher.initialiseCipher(key);
        cipher.initialiseIV(iv);

        byte[] block = new byte[16];
        final int iterations = 1000000 / 16 + 1;

        for (int i = 0; i < iterations; i++) {
            cipher.encrypt(block);
        }

        byte[] target = new byte[] { 52, -18, 60, 82, -27, -23, -13, 75, -60, -62, -23, -106, -47, 80, 123, -26 };

        assertArrayEquals(target, block);
    }

    @Test
    @Order(2)
    void long10MBTest() {
        byte[] key = new byte[] { -6, -23, -40, -57, -74, -91, -76, -61, -46, -31, -16, 15, 30, 45, 60, 75 };
        byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 };

        cipher.initialiseCipher(key);
        cipher.initialiseIV(iv);

        byte[] block = new byte[16];
        final int iterations = 10000000 / 16 + 1;

        for (int i = 0; i < iterations; i++) {
            cipher.encrypt(block);
        }

        byte[] target = new byte[] { -42, -22, 45, 26, -81, 11, -93, 41, 56, 59, 13, 24, -45, -4, -121, 26 };

        assertArrayEquals(target, block);
    }
}
