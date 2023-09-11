package uk.ac.nottingham.cryptography;

public class Main {
    public static void main(String[] args) {

        byte[] key = new byte[] { (byte)0xAC, (byte)0xC3, 0x51, (byte)0xDC, (byte)0xF1, 0x62,
                (byte)0xFC, 0x3B, (byte)0xFE, 0x36, (byte)0x3D, 0x2E, 0x29, 0x13, 0x28, (byte)0x91};

        byte[] iv = new byte[] { (byte)0x59, (byte)0x7E, (byte)0x26, (byte)0xC1, (byte)0x75, (byte)0xF5, (byte)0x73, (byte)0xC3};


        RabbitCipher rabbit = new Rabbit();
        rabbit.initialiseCipher(key);
        System.out.println(rabbit.getStateString(RabbitCipher.StringOutputFormatting.FANCY));
        rabbit.initialiseIV(iv);
        System.out.println(rabbit.getStateString(RabbitCipher.StringOutputFormatting.FANCY));
    }
}



