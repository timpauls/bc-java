package org.bouncycastle.jce.provider.test;

import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * Test for the SRA JCE provider
 *
 * TODO: not really on par with {@link org.bouncycastle.jce.provider.test.RSATest} ;-)
 */
public class SRATest extends SimpleTest {
    private static final int KEY_SIZE = 2048;
    private static final String PLAIN_TEXT = "A quick movement of the enemy will jeopardize six gunboats";

    @Override
    public String getName() {
        return "SRATest";
    }

    @Override
    public void performTest() throws Exception {
        standardKeyPairGenerationAndEnDecryption();
        //TODO: test with given p and q.
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

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SRATest());
    }
}
