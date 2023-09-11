package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.*;

import java.util.Random;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class InitialisationTests {

    private final RabbitCipher cipher = ServiceLoader.load(RabbitCipher.class).findFirst().orElseThrow();

    private static final String EXP_ZERO_KEY_STATE = "6E9E1D18 F5A54E5C F8FD49C6 9B94253F DCD14A79 1F32FA20 D2055921 53F371D0 E802074F 5206296D 01486DF2 67203CE4 23AACE55 26E87A8F CC2E04F2 D6A0F672 1";

    @Test
    @Order(1)
    void initialiseFromZeroKeyTest() {
        cipher.initialiseCipher(new byte[16]);
        String cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(EXP_ZERO_KEY_STATE, cipherState);
    }

    @Test
    @Order(2)
    void extendedKeyInitTests() {
        byte[][] testKeys = new byte[][] {
                { 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0 },
                {(byte)0xAC,(byte)0xC3,0x51,(byte)0xDC,(byte)0xF1,0x62,(byte)0xFC,0x3B,(byte)0xFE,0x36, (byte)0x3D, 0x2E, 0x29, 0x13, 0x28, (byte)0x91},
                {(byte)0xF0,(byte)0xE1,(byte)0xD2,(byte)0xC3,(byte)0xB4,(byte)0xA5,(byte)0x96,(byte)0x87,
                        (byte)0x78, (byte)0x69, (byte)0x5A, (byte)0x4B, (byte)0x3C, (byte)0x2D, (byte)0x1E, (byte)0x0F}
        };

        String[] testStates = new String[] {
                "854CDD00 DB30DFAD 516CEDC8 E7848FA2 A6F6C0C6 0C8B08D2 5156270D 5E47E0F9 9C2C91FD 55CAD58A 840613D9 629BB3C2 DE0F025A 0C62E97B 6FB2B8F5 AAB16EFE 1",
                "1D059312 BDDC3E45 F440927D 50CBB553 36709423 0B6F0711 3ADA3A7B EB9800C8 5DA1EF57 22E9312F DCACFF87 9B5784FA 0DE43C8C BC5679B8 63841B4C 8E9623AA 0",
                "BD37DC44 416F631E D917BCF9 F37D7FDC D9E41C4F 46BA596C 5D0B7468 58EBBE16 47AF84DF 57BD206D 5D82379A E48208BB 92124B5B 5FC8010E 03906832 AF2ECAE1 1"
        };

        for (int i = 0; i < testKeys.length; i++) {
            cipher.initialiseCipher(testKeys[i]);
            String initState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
            assertEquals(testStates[i], initState);
        }
    }

    @Test
    @Order(3)
    void singleIvInitTest() {
        // Ensure we can initialise the cipher using a key first
        cipher.initialiseCipher(new byte[16]);
        String cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assumeTrue(EXP_ZERO_KEY_STATE.equals(cipherState));

        byte[] testIV = new byte[] { (byte)0xFA, 0x3E, 0x32, (byte)0xCD, (byte)0xA4, 0x02, (byte)0xFE, 0x01 };

        String expectedState = "143DAB82 15D8A3E8 4C6E3CA4 C8505533 CE271207 6946D0BF C5D4A680 AC7D4B95 5A0386ED A12DB7AC D403A429 9A574F52 3BCDC3FC FA63EC91 02A3538A 21399BD6 1";

        cipher.initialiseIV(testIV);
        String ivState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(expectedState, ivState);
    }

    @Test
    @Order(3)
    void nullOrZeroIvInitTest() {
        // Ensure we can initialise the cipher using a key first
        cipher.initialiseCipher(new byte[16]);
        String cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assumeTrue(EXP_ZERO_KEY_STATE.equals(cipherState));

        // Null cipher should not alter the state
        cipher.initialiseIV(null);
        cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(EXP_ZERO_KEY_STATE, cipherState);

        cipher.initialiseIV(new byte[8]);
        String zeroIVState = "825CE07B 12633711 A0FE547B 75CF0E64 92EF9246 89E633C7 2C7442FF 2C6B4782 1CD55487 9F3AFCBB D495A2C5 9BF38A18 70DFA1A2 FA35AF62 01015226 23D5C9C0 1";
        cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(zeroIVState, cipherState);
    }

    @Test
    @Order(4)
    void ivReInitTest() {
        // Ensure we can initialise the cipher using a key first
        cipher.initialiseCipher(new byte[16]);
        String cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assumeTrue(EXP_ZERO_KEY_STATE.equals(cipherState));

        byte[] testIVOne = new byte[] { (byte)0xFA, 0x3E, 0x32, (byte)0xCD, (byte)0xA4, 0x02, (byte)0xFE, 0x01 };
        byte[] testIVTwo = new byte[] { (byte)0xAF, (byte)0xB7, (byte)0xCB, 0x00, (byte)0xA0, 0x4C, (byte)0xDA, 0x19 };

        // Apply IV One
        cipher.initialiseIV(testIVOne);
        String ivOneState = "143DAB82 15D8A3E8 4C6E3CA4 C8505533 CE271207 6946D0BF C5D4A680 AC7D4B95 5A0386ED A12DB7AC D403A429 9A574F52 3BCDC3FC FA63EC91 02A3538A 21399BD6 1";
        cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(ivOneState, cipherState);

        // IV Two Reinitialise
        cipher.initialiseIV(testIVTwo);
        String ivTwoState = "4D551582 C95BFC66 51D4DFF1 AEB269D5 9AB5B427 C4A273F8 98ED98CC 825B40F2 1D9CFE18 9910FCF4 EBDF5625 6053D87F 70964D47 127FAF17 0AC79587 E735152B 0";
        cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(ivTwoState, cipherState);

        // IV One Reinitialise
        cipher.initialiseIV(testIVOne);
        cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(ivOneState, cipherState);
    }

    @Test
    @Order(5)
    void multiKeyIVTests() {
        byte[][] testKeys = new byte[][] {
                { 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0 },
                {(byte)0xAC,(byte)0xC3,0x51,(byte)0xDC,(byte)0xF1,0x62,(byte)0xFC,0x3B,(byte)0xFE,0x36, (byte)0x3D, 0x2E, 0x29, 0x13, 0x28, (byte)0x91},
                {(byte)0xF0,(byte)0xE1,(byte)0xD2,(byte)0xC3,(byte)0xB4,(byte)0xA5,(byte)0x96,(byte)0x87,
                        (byte)0x78, (byte)0x69, (byte)0x5A, (byte)0x4B, (byte)0x3C, (byte)0x2D, (byte)0x1E, (byte)0x0F}
        };

        byte[][] testIVs = new byte[][] {
                null,
                { 1, 0, 0, 0, 0, 0, 0, 0 },
                { 0x0E, (byte)0xB0, 0x04, (byte)0xD0, 0x01, 0x09, (byte)0xA0, (byte)0xF0 }
        };

        String[] expectedOutputs = new String[] {
                "854CDD00 DB30DFAD 516CEDC8 E7848FA2 A6F6C0C6 0C8B08D2 5156270D 5E47E0F9 9C2C91FD 55CAD58A 840613D9 629BB3C2 DE0F025A 0C62E97B 6FB2B8F5 AAB16EFE 1",
                "541B47F9 FA068DEC BEE22902 1A246E1F 253BB501 8081C9CD 4A792514 E370E49D D0FFDF34 A2FFA8D7 575348AC 976F00F8 2B43D5A8 DFB01E4F A4860629 F7E6424C 0",
                "C6D53C0A 4B6DF2FE A4F7768C BD045176 00479F86 D9385DDF D39D63D3 672C6FBC 80FB6F2B F29ED8DB 47F34FAB A06D5101 5B4085A1 D00F6E52 D3E5FF29 F0E5B23D 0",
                "1D059312 BDDC3E45 F440927D 50CBB553 36709423 0B6F0711 3ADA3A7B EB9800C8 5DA1EF57 22E9312F DCACFF87 9B5784FA 0DE43C8C BC5679B8 63841B4C 8E9623AA 0",
                "C4417724 B34450D3 E69110F5 38C5D75F FE252E28 9DCC0944 97B88C69 77BAD4E8 92753C8D 701E047C AFFA345A D02AD230 5B190FDA 8FA3AE8B 98576881 DBCAF6F8 0",
                "CF5A605A C70909B4 3FAB8C42 C2322BE2 13DF34DF E04C7AE1 B4619B55 1276945D C278AC90 1F7EB478 FF5A2B5A C7298228 2B155FCF 2043DE90 C7F75F82 D4CC66F1 0",
                "BD37DC44 416F631E D917BCF9 F37D7FDC D9E41C4F 46BA596C 5D0B7468 58EBBE16 47AF84DF 57BD206D 5D82379A E48208BB 92124B5B 5FC8010E 03906832 AF2ECAE1 1",
                "3533BD4F 1DA4A544 E17051C9 E05E5F0A 5B348A16 A2EC7854 97D83BCF 87F90CD5 7C82D216 A4F1F3BA 30CF6C6D 195555EF DF471EA8 331535E1 3863B567 FC639E2D 0",
                "6AC4A03D 84040A14 F3024C5F C074BC67 77B24909 0839C0C7 37E53052 6F4D3A68 CC7E8209 F452C3B6 806F736E 225705EA 8F4BCEA3 82B605DD 2803AE68 F3644E3D 0",
        };

        // Bootstrap cipher with zero key
        cipher.initialiseCipher(new byte[16]);
        String cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assumeTrue(EXP_ZERO_KEY_STATE.equals(cipherState));

        for (int i = 0; i < 3 * 3; i++) {
            int ki = i / 3;
            int ivi = i % 3;
            cipher.initialiseCipher(testKeys[ki]);
            cipher.initialiseIV(testIVs[ivi]);
            cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
            assertEquals(expectedOutputs[i], cipherState);
        }
    }


}
