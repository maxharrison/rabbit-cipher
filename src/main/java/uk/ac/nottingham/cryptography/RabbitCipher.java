package uk.ac.nottingham.cryptography;

public interface RabbitCipher {
    enum StringOutputFormatting
    {
        PLAIN, FANCY
    }

    void initialiseCipher(byte[] key);

    void initialiseIV(byte[] iv);

    void counterUpdate();

    void nextState();

    void encrypt(byte[] block);

    void decrypt(byte[] block);

    void encryptMessage(byte[] iv, byte[] message);

    void decryptMessage(byte[] iv, byte[] message);

    String getStateString(StringOutputFormatting formatting);
}
