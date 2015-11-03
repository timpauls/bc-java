package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.generators.SRAKeyParametersGenerator;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SRATest extends SimpleTest {
    public static final int KEY_SIZE_IN_BIT = 2048;
    public static final int CERTAINTY = 80;
    static String input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

    //
    // to check that we handling byte extension by big number correctly.
    //
    static String edgeInput = "ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";
    private SecureRandom secureRandom;
    private SRAKeyParametersGenerator keyParamGenerator;

    public String getName()
    {
        return "SRA";
    }

    private void setup() {
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
            keyParamGenerator = new SRAKeyParametersGenerator();
            keyParamGenerator.init(KEY_SIZE_IN_BIT, CERTAINTY, secureRandom);
        } catch (NoSuchAlgorithmException e) {
            fail("failed - no such SecureRandom algorithm");
        }
    }

    public void performTest() {
        setup();

        testKeyParameterGeneration();
        testEncryptionDecryption();
        testCommutativity();
    }

    private void testKeyParameterGeneration() {
        try {
            SRAKeyParametersGenerator generator = new SRAKeyParametersGenerator();
            generator.init(KEY_SIZE_IN_BIT, CERTAINTY, secureRandom);
            generator.generateParameters();
        } catch (IllegalArgumentException e) {
            fail("key parameter generation failed", e);
        }
    }

    private void testEncryptionDecryption() {
        SRAKeyPairGenerator sraKeyPairGenerator = new SRAKeyPairGenerator();
        SRAKeyGenerationParameters sraKeyGenerationParameters = keyParamGenerator.generateParameters();
        sraKeyPairGenerator.init(sraKeyGenerationParameters);
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = sraKeyPairGenerator.generateKeyPair();

        byte[] data = Hex.decode(edgeInput);

        SRAEngine sraEngine = new SRAEngine();
        sraEngine.init(true, asymmetricCipherKeyPair.getPublic());
        byte[] cipher = sraEngine.processBlock(data, 0, data.length);

        sraEngine.init(false, asymmetricCipherKeyPair.getPrivate());
        byte[] decrypted = sraEngine.processBlock(cipher, 0, cipher.length);

        if (!Arrays.areEqual(data, decrypted)) {
            fail ("failed - decryption does not equal original data!");
        }
    }

    /**
     * Test commutativity:
     * Da(Eb(Ea(M))) = Eb(M)
     */
    private void testCommutativity() {
        // Alice
        SRAKeyPairGenerator sraKeyPairGeneratorAlice = new SRAKeyPairGenerator();
        SRAKeyGenerationParameters params = keyParamGenerator.generateParameters();
        sraKeyPairGeneratorAlice.init(params);
        AsymmetricCipherKeyPair asymmetricCipherKeyPairAlice = sraKeyPairGeneratorAlice.generateKeyPair();

        // Bob
        SRAKeyPairGenerator sraKeyPairGeneratorBob = new SRAKeyPairGenerator();

        sraKeyPairGeneratorBob.init(new SRAKeyGenerationParameters(params.getP(), params.getQ(), secureRandom, KEY_SIZE_IN_BIT, CERTAINTY));
        AsymmetricCipherKeyPair asymmetricCipherKeyPairBob = sraKeyPairGeneratorBob.generateKeyPair();

        byte[] data = Hex.decode(edgeInput);
        SRAEngine sraEngine = new SRAEngine();

        // Encode first with Alice's key, then with Bob's
        sraEngine.init(true, asymmetricCipherKeyPairAlice.getPublic());
        byte[] cipherAlice = sraEngine.processBlock(data, 0, data.length);

        sraEngine.init(true, asymmetricCipherKeyPairBob.getPublic());
        byte[] cipherAliceBob = sraEngine.processBlock(cipherAlice, 0, cipherAlice.length);

        // decrypt with Alice's key
        sraEngine.init(false, asymmetricCipherKeyPairAlice.getPrivate());
        byte[] decryptedAlice = sraEngine.processBlock(cipherAliceBob, 0, cipherAliceBob.length);

        // encrypt plaintext just with Bob's key
        sraEngine.init(true, asymmetricCipherKeyPairBob.getPublic());
        byte[] cipherBob = sraEngine.processBlock(data, 0, data.length);

        if (!Arrays.areEqual(decryptedAlice, cipherBob)) {
            fail ("failed - encryption is not commutative!");
        }
    }

    public static void main(String[]    args) {
        runTest(new SRATest());
    }
}
