package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.generators.SRAKeyParametersGenerator;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SRATest extends SimpleTest {
    static BigInteger  p = new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16);
    static BigInteger  q = new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16);

    static String input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

    //
    // to check that we handling byte extension by big number correctly.
    //
    static String edgeInput = "ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";
    private SecureRandom secureRandom;

    public String getName()
    {
        return "SRA";
    }

    public void performTest() {
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
            testKeyParameterGeneration();
            testEncryptionDecryption();
            testCommutativity();
        } catch (NoSuchAlgorithmException e) {
            fail("failed - no such SecureRandom algorithm");
        }
    }

    private void testKeyParameterGeneration() {
        try {
            SRAKeyParametersGenerator generator = new SRAKeyParametersGenerator();
            generator.init(2048, 80, secureRandom);
            generator.generateParameters();
        } catch (IllegalArgumentException e) {
            fail("key parameter generation failed", e);
        }
    }

    private void testEncryptionDecryption() throws NoSuchAlgorithmException {
        SRAKeyPairGenerator sraKeyPairGenerator = new SRAKeyPairGenerator();
        // TODO: replace constructor with generator
        sraKeyPairGenerator.init(new SRAKeyGenerationParameters(p, q, SecureRandom.getInstance("SHA1PRNG"), 5, 5));
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
    private void testCommutativity() throws NoSuchAlgorithmException {
        // Alice
        SRAKeyPairGenerator sraKeyPairGeneratorAlice = new SRAKeyPairGenerator();
        // TODO: replace constructor with generator
        sraKeyPairGeneratorAlice.init(new SRAKeyGenerationParameters(p, q, SecureRandom.getInstance("SHA1PRNG"), 5, 5));
        AsymmetricCipherKeyPair asymmetricCipherKeyPairAlice = sraKeyPairGeneratorAlice.generateKeyPair();

        // Bob
        SRAKeyPairGenerator sraKeyPairGeneratorBob = new SRAKeyPairGenerator();
        // TODO: replace constructor with generator
        sraKeyPairGeneratorBob.init(new SRAKeyGenerationParameters(p, q, SecureRandom.getInstance("SHA1PRNG"), 5, 5));
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
