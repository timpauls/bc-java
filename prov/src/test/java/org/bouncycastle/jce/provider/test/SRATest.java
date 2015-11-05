package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jcajce.provider.asymmetric.sra.SRAKeyGenParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Test for the SRA JCE provider
 *
 * TODO: not really on par with {@link org.bouncycastle.jce.provider.test.RSATest} ;-)
 */
public class SRATest extends SimpleTest {
    private static final int KEY_SIZE = 2048;
    private static final String PLAIN_TEXT = "A quick movement of the enemy will jeopardize six gunboats";

    final static BigInteger DEFAULT_P = new BigInteger("f2ac535b14a36b3707988f789d2ffd9d407e2ce1c387382678bf33932ebf708d067f2b2425704ddb7b708d51f94c7ee5868db43acc2649d611f71f5f4acd69b1b136fde10b5c4f70fe5f3a201aa2fdb79add4065d82bcc6460d8dac58906b4a856cb57317500c176ab8af9aa9e5f667c458c9ab70837f2f06bd1d2c2f1b7b50d", 16);
    final static BigInteger DEFAULT_Q = new BigInteger("c4f0f0d53e216ce3d8ccef361026b88bd07a14985a81d74772937f1b2be85e22b24dbf41f7e7a62232f7254f090b20f23d1dcb47a18e7438756e43c62b12b611c95f0cb0b7cc03dbd6c08601240857b09247b66fc420ab80e934a8e3bd17fafa233defbbad61cd27f98dda348f72a0f7d21309e16d1c69b235b8f149a3b637df", 16);

    @Override
    public String getName() {
        return "SRATest";
    }

    @Override
    public void performTest() throws Exception {
        standardKeyPairGenerationAndEnDecryption();
        keyPairGenerationAndEnDecryptionWithGivenPQ();
        checkPQ();
    }

    private void standardKeyPairGenerationAndEnDecryption() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(KEY_SIZE);

        KeyPair keyPair = generator.generateKeyPair();

        Cipher engine = Cipher.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);

        System.out.println("Plain: " + PLAIN_TEXT);

        engine.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] cipher = engine.doFinal(PLAIN_TEXT.getBytes());

        System.out.println("Cipher: " + Hex.toHexString(cipher));

        engine.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decipher = engine.doFinal(cipher);

        String decipherString = new String(decipher);

        System.out.println("Decipher: " + decipherString);

        if (!PLAIN_TEXT.equals(decipherString)) {
            fail("failed - encryption and decryption did not restore plain text.");
        }
    }

    private void keyPairGenerationAndEnDecryptionWithGivenPQ() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SRAKeyGenParameterSpec sraKeyGenParameterSpec = new SRAKeyGenParameterSpec(KEY_SIZE, DEFAULT_P, DEFAULT_Q);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
        try {
            generator.initialize(sraKeyGenParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            fail("failed - invalid algorithm parameters", e);
        }
        KeyPair keyPair = generator.generateKeyPair();

        Cipher engine = Cipher.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);

        System.out.println("Plain: " + PLAIN_TEXT);

        engine.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] cipher = engine.doFinal(PLAIN_TEXT.getBytes());

        System.out.println("Cipher: " + Hex.toHexString(cipher));

        engine.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decipher = engine.doFinal(cipher);

        String decipherString = new String(decipher);

        System.out.println("Decipher: " + decipherString);

        if (!PLAIN_TEXT.equals(decipherString)) {
            fail("failed - encryption and decryption did not restore plain text.");
        }
    }

    private void checkPQ() throws NoSuchProviderException, NoSuchAlgorithmException {
        SRAKeyGenParameterSpec sraKeyGenParameterSpec = new SRAKeyGenParameterSpec(KEY_SIZE, DEFAULT_P, DEFAULT_Q);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
        try {
            generator.initialize(sraKeyGenParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            fail("failed - invalid algorithm parameters", e);
        }
        KeyPair keyPair = generator.generateKeyPair();
        BigInteger privateKeyModulus = ((RSAPrivateKey) keyPair.getPrivate()).getModulus();
        BigInteger publicKeyModulus = ((RSAPublicKey) keyPair.getPublic()).getModulus();
        BigInteger myModulus = DEFAULT_P.multiply(DEFAULT_Q);

        if (!privateKeyModulus.equals(publicKeyModulus)) {
            fail("failed - public and private key moduli are not the same!");
        }

        if (!privateKeyModulus.equals(myModulus)) {
            fail("failed - generated key pair modulus does not equal expected modulus!");
        }
    }



    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SRATest());
    }
}
