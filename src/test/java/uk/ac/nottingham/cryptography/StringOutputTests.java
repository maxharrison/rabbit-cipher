package uk.ac.nottingham.cryptography;

import org.junit.jupiter.api.*;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class StringOutputTests {

    private final RabbitCipher cipher = ServiceLoader.load(RabbitCipher.class).findFirst().orElseThrow();

    private static final String EXP_ZERO_KEY_STATE_PLAIN = "6E9E1D18 F5A54E5C F8FD49C6 9B94253F DCD14A79 1F32FA20 D2055921 53F371D0 E802074F 5206296D 01486DF2 67203CE4 23AACE55 26E87A8F CC2E04F2 D6A0F672 1";

    private static final String EXP_ZERO_KEY_STATE_FANCY = """
    b = 1
    X0 = 0x6E9E1D18, X1 = 0xF5A54E5C, X2 = 0xF8FD49C6, X3 = 0x9B94253F,
    X4 = 0xDCD14A79, X5 = 0x1F32FA20, X6 = 0xD2055921, X7 = 0x53F371D0,
    C0 = 0xE802074F, C1 = 0x5206296D, C2 = 0x01486DF2, C3 = 0x67203CE4,
    C4 = 0x23AACE55, C5 = 0x26E87A8F, C6 = 0xCC2E04F2, C7 = 0xD6A0F672""";

    @Test
    void getStateStringTestPlain() {
        cipher.initialiseCipher(new byte[16]);
        String cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.PLAIN);
        assertEquals(EXP_ZERO_KEY_STATE_PLAIN, cipherState);
    }

    @Test
    void getStateStringTestFancy() {
        cipher.initialiseCipher(new byte[16]);
        String cipherState = cipher.getStateString(RabbitCipher.StringOutputFormatting.FANCY);
        assertEquals(EXP_ZERO_KEY_STATE_FANCY, cipherState);
    }




}
