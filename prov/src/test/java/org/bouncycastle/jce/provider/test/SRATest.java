package org.bouncycastle.jce.provider.test;

import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.security.*;

/**
 * Test for the SRA JCE provider
 *
 * TODO: not really on par with {@link org.bouncycastle.jce.provider.test.RSATest} ;-)
 */
public class SRATest extends SimpleTest {
    private static final int KEY_SIZE = 128;
    private static final String PLAIN_TEXT = "A quick movement of the enemy will jeopardize six gunboats";

    @Override
    public String getName() {
        return "SRATest";
    }

    @Override
    public void performTest() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(KEY_SIZE);

        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        SRAEngine sraEngine = new SRAEngine();

        System.out.println("Plain: " + PLAIN_TEXT);

        sraEngine.init(true, PublicKeyFactory.createKey(publicKey.getEncoded()));
        byte[] cipher = sraEngine.processBlock(PLAIN_TEXT.getBytes(), 0, PLAIN_TEXT.getBytes().length);
        System.out.println("Cipher: " + Hex.toHexString(cipher));

        sraEngine.init(false, PrivateKeyFactory.createKey(privateKey.getEncoded()));
        byte[] decrypted = sraEngine.processBlock(cipher, 0, cipher.length);
        System.out.println("Decrypted: " + new String(decrypted));

        if (!PLAIN_TEXT.equals(new String(decrypted))) {
            fail("failed - encryption and decryption did not restore original plain text");
        }
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new SRATest());
    }
}
