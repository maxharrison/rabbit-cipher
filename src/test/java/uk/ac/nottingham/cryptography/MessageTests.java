package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.*;

import java.util.Arrays;
import java.util.Random;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.*;
import static uk.ac.nottingham.cryptography.EncryptTests.rand;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class MessageTests {

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
    void encryptSingleBlockSingleMessageTest() {
        byte[] key = new byte[]{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
        byte[] iv = new byte[] {(byte) 0xFF, (byte) 0xFE, (byte) 0xFD, (byte) 0xFC, (byte) 0xFB, (byte) 0xFA, (byte) 0xEF, (byte) 0xEE };
        cipher.initialiseCipher(key);

        byte[] plaintext = new byte[]{-93, 1, -26, -4, -64, 2, -23, 122, -44, -72, 8, 9, 31, 100, -80, 115};
        byte[] expectedBlock = {65, -60, 51, -40, -15, -72, -66, 55, -75, -62, -12, -40, 102, 19, 63, -58};
        byte[] encryptedBlock = Arrays.copyOf(plaintext, plaintext.length);

        cipher.encryptMessage(iv, encryptedBlock);

        assertArrayEquals(expectedBlock, encryptedBlock);
    }

    @Test
    @Order(1)
    void encryptSingleBlockMultiMessageTest() {
        byte[] key = new byte[]{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
        byte[] ivM1 = new byte[] {(byte) 0xFF, (byte) 0xFE, (byte) 0xFD, (byte) 0xFC, (byte) 0xFB, (byte) 0xFA, (byte) 0xEF, (byte) 0xEE };
        byte[] ivM2 = new byte[] { 4, 3, 2, 1, 9, 8, 7, 6};

        cipher.initialiseCipher(key);

        byte[] plaintext = new byte[]{-93, 1, -26, -4, -64, 2, -23, 122, -44, -72, 8, 9, 31, 100, -80, 115};
        byte[] expectedBlockM1 = { 65, -60, 51, -40, -15, -72, -66, 55, -75, -62, -12, -40, 102, 19, 63, -58};
        byte[] expectedBlockM2 = { 18, 47, 82, -6, 71, -49, -7, -13, 61, 69, -22, 43, -86, -118, 63, -10 };
        byte[] encryptedBlockM1 = Arrays.copyOf(plaintext, plaintext.length);
        byte[] encryptedBlockM2 = Arrays.copyOf(plaintext, plaintext.length);

        cipher.encryptMessage(ivM1, encryptedBlockM1);
        cipher.encryptMessage(ivM2, encryptedBlockM2);

        assertArrayEquals(expectedBlockM1, encryptedBlockM1);
        assertArrayEquals(expectedBlockM2, encryptedBlockM2);
    }

    @Test
    @Order(3)
    void encryptMultiBlockSingleMessageTest() {
        byte[] key = hexStringToByteArray("01 03 05 07 09 11 13 15 17 19 21 23 25 27 29 31");
        byte[] iv =  hexStringToByteArray("A1 B2 A3 C4 A5 D6 A7 E8");

        cipher.initialiseCipher(key);
        cipher.initialiseIV(iv);

        byte[] message = hexStringToByteArray("7D 03 B5 70 37 49 64 C4 7D 14 D7 02 22 91 38 B9 81 98 53 ED B5 13 15 AF 7D 86 52 A5 1A 97 78 40 63 AA 3A 6E 2C 39 52 54 74 7E AB CE A7 66 55 21 A1 A7 10 02 38 53 7E E1 9B AA F7 7C E2 9A 63 C2");
        byte[] expectedMessage = hexStringToByteArray("70 9E 64 77 B1 ED A3 9D 8D CF 44 5B B6 6E A8 9F 19 6C EA 50 11 1F 89 F5 64 7A 5B 60 C5 EF 9C F4 56 2F 57 62 43 BC 45 D8 C3 77 A7 BC 60 56 D4 98 1D 8F D4 08 C0 2D 29 6A 6C C4 EB 9D F8 CD 34 69");
        byte[] encryptedBlock = Arrays.copyOf(message, message.length);
        cipher.encryptMessage(iv, encryptedBlock);

        assertArrayEquals(expectedMessage, encryptedBlock);
    }

    @Test
    @Order(4)
    void encryptMultiBlockMultiMessageTest() {
        byte[] key = hexStringToByteArray("01 03 05 07 09 11 13 15 17 19 21 23 25 27 29 31");

        byte[][] ivs = new byte[][] {
                hexStringToByteArray("A1 B2 A3 C4 A5 D6 A7 E8"),
                hexStringToByteArray("FA 3D DE 9B CA 8A E4 12"),
                hexStringToByteArray("FF FE FD FC FB FA F9 F8")
        };

        cipher.initialiseCipher(key);

        byte[][] messages = new byte[][] {
                hexStringToByteArray("A9 10 E1 3E 1F F7 9C 21 48 A5 08 BB 87 D7 F1 F4 61 11 DF 7C 85 73 90 FF 75 D1 62 45 20 D5 F7 6D"),
                hexStringToByteArray("FC 06 E4 E8 A0 9A EA 7A 70 71 4A 0B A6 25 D9 39 9F 5B 5F 48 8D FC F1 7E 57 EE A0 7A 18 7C 33 CC DD E1 C5 1E B3 7A 0A 9A D3 E9 AB 3E D2 D3 0F 0A"),
                hexStringToByteArray("7D 03 B5 70 37 49 64 C4 7D 14 D7 02 22 91 38 B9 81 98 53 ED B5 13 15 AF 7D 86 52 A5 1A 97 78 4063 AA 3A 6E 2C 39 52 54 74 7E AB CE A7 66 55 21A1 A7 10 02 38 53 7E E1 9B AA F7 7C E2 9A 63 C2")
        };

        byte[][] expectedMessages = new byte[][] {
                hexStringToByteArray("A4 8D 30 39 99 53 5B 78 B8 7E 9B E2 13 28 61 D2 F9 E5 66 C1 21 7F 0C A5 6C 2D 6B 80 FF AD 13 D9"),
                hexStringToByteArray("61 8C 84 8A CB 5C D1 39 3F 9E 2A 6C EF 58 AC 0E 23 17 05 7A 5B 43 DA 69 19 0A 67 64 30 23 E3 F1 DF E6 DA 9C B0 E5 30 74 FE 07 92 9B 87 B6 10 DB"),
                hexStringToByteArray("7E 07 C8 23 2D 13 94 4B 62 A5 A1 B8 5E 6D 0F 60 01 64 4D 0A 7C F1 6A F2 43 1D 06 39 8A 4C 81 17 3D 92 E9 AD 63 6F BA 69 D9 89 1B 85 7A 56 94 49 A6 49 1D B1 85 5A 4A 6C 14 2D 2D D9 40 ED BB D7")
        };

        for (int i = 0; i < messages.length; i++) {
            byte[] encryptedBlock = Arrays.copyOf(messages[i], messages[i].length);
            cipher.encryptMessage(ivs[i], encryptedBlock);
            String s = byteArrayToHex(encryptedBlock);
            assertArrayEquals(expectedMessages[i], encryptedBlock);
        }
    }

    @Test
    @Order(5)
    void encryptSinglePartialBlockTest() {
        byte[] key = hexStringToByteArray("01 03 05 07 09 11 13 15 17 19 21 23 25 27 29 31");
        byte[] iv =  hexStringToByteArray("A1 B2 A3 C4 A5 D6 A7 E8");

        cipher.initialiseCipher(key);
        cipher.initialiseIV(iv);

        byte[] message = hexStringToByteArray("7D 03 B5 70 37 49 64 C4 7D 14 D7 02 22 91 38 B9 81 98 53 ED B5 13 15");
        byte[] expectedMessage = hexStringToByteArray("70 9E 64 77 B1 ED A3 9D 8D CF 44 5B B6 6E A8 9F 19 6C EA 50 11 1F 89");
        byte[] encryptedBlock = Arrays.copyOf(message, message.length);
        cipher.encryptMessage(iv, encryptedBlock);

        assertArrayEquals(expectedMessage, encryptedBlock);
    }

    @Test
    @Order(5)
    void encryptMultiPartialBlockTest() {
        byte[] key = hexStringToByteArray("01 03 05 07 09 11 13 15 17 19 21 23 25 27 29 31");
        byte[] iv =  hexStringToByteArray("A1 B2 A3 C4 A5 D6 A7 E8");

        cipher.initialiseCipher(key);
        cipher.initialiseIV(iv);

        byte[] message = hexStringToByteArray("7D 03 B5 70 37 49 64 70 71 4A 0B A6 25 D9 39 9F 5B 5F 48 8D FC F1 7E 57 EE A0 7A 18 7C 33 CC DD E1 C5 1E B9 81 98 53 ED B5 13 15");
        byte[] expectedMessage = hexStringToByteArray("70 9E 64 77 B1 ED A3 29 81 91 98 FF B1 26 A9 B9 C3 AB F1 30 58 FD E2 0D F7 5C 73 DD A3 4B 28 69 D4 40 73 B5 EE 1D 44 61 02 1A 19");
        byte[] encryptedBlock = Arrays.copyOf(message, message.length);
        cipher.encryptMessage(iv, encryptedBlock);
        String s = byteArrayToHex(encryptedBlock);
        assertArrayEquals(expectedMessage, encryptedBlock);
    }

    @Test
    @Order(6)
    void extendedRandomMessageEncryptDecrypt() {
        for (int k = 0; k < 5; k++) {
            byte[] key = getRandomKey();
            cipher.initialiseCipher(key);

            for (int i = 0; i < 5; i++) {
                byte[] iv = getRandomIV();
                byte[] message = getRandomMessage(10, 1024);
                byte[] encryptedBlock = Arrays.copyOf(message, message.length);

                cipher.encryptMessage(iv, encryptedBlock);
                assertFalse(Arrays.equals(message, encryptedBlock));

                cipher.decryptMessage(iv, encryptedBlock);
                assertArrayEquals(message, encryptedBlock);
            }
        }
    }

    static byte[] getRandomMessage(int minLength, int maxLength) {
        int length = rand.nextInt(maxLength - minLength + 1) + minLength;
        byte[] bl = new byte[length];
        rand.nextBytes(bl);
        return bl;
    }

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


    // Byte array to hex in LSB to MSB order
    static String byteArrayToHex(byte[] block) {
        StringBuilder sb = new StringBuilder();
        for (byte b : block) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    // Hex to byte array in LSB to MSB order
    public static byte[] hexStringToByteArray(String s) {
        s = s.replace(" ", "");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[(i / 2)] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
