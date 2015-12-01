package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jcajce.provider.asymmetric.sra.SRADecryptionKeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.sra.SRAEncryptionKeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.sra.SRAKeyGenParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

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
        standardKeyPairGenerationAndEnDecryptionWithOAEPPadding();
        OAEPPaddingNonDeterministic();
        restoreKeyPairWithKeyFactoryTest();
        restorePandQFromGeneratedKeys();
        restoreKeyAndUseIt();
    }

    private void standardKeyPairGenerationAndEnDecryption() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("standardKeyPairGenerationAndEnDecryption");
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

    private void standardKeyPairGenerationAndEnDecryptionWithOAEPPadding() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("standardKeyPairGenerationAndEnDecryptionWithOAEPPadding");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(KEY_SIZE);

        KeyPair keyPair = generator.generateKeyPair();

        Cipher engine = Cipher.getInstance("SRA/NONE/OAEPPADDING", BouncyCastleProvider.PROVIDER_NAME);

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

    private void OAEPPaddingNonDeterministic() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("OAEPPaddingNonDeterministic");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(KEY_SIZE);

        KeyPair keyPair = generator.generateKeyPair();

        Cipher engine = Cipher.getInstance("SRA/NONE/OAEPPADDING", BouncyCastleProvider.PROVIDER_NAME);

        System.out.println("Plain: " + PLAIN_TEXT);

        engine.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] cipher = engine.doFinal(PLAIN_TEXT.getBytes());

        System.out.println("Cipher1: " + Hex.toHexString(cipher));

        byte[] cipherTwo = engine.doFinal(PLAIN_TEXT.getBytes());

        if (Arrays.areEqual(cipher, cipherTwo)) {
            fail("failed - was deterministic with padding.");
        }

        System.out.println("Cipher2: " + Hex.toHexString(cipherTwo));

        engine.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decipher = engine.doFinal(cipher);

        String decipherString = new String(decipher);

        System.out.println("Decipher1: " + decipherString);

        byte[] decipherTwo = engine.doFinal(cipherTwo);
        String decipherStringTwo = new String(decipherTwo);

        System.out.println("Decipher2: " + decipherStringTwo);

        if (!PLAIN_TEXT.equals(decipherString)) {
            fail("failed - encryption and decryption did not restore plain text.");
        }

        if (!PLAIN_TEXT.equals(decipherStringTwo)) {
            fail("failed - encryption and decryption of 2nd attempt did not restore plain text");
        }
    }

    private void keyPairGenerationAndEnDecryptionWithGivenPQ() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("keyPairGenerationAndEnDecryptionWithGivenPQ");
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
        System.out.println("checkPQ");
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

    private void restoreKeyPairWithKeyFactoryTest() {
        System.out.println("restoreKeyPairWithKeyFactoryTest");

        SRAKeyGenParameterSpec sraKeyGenParameterSpec = new SRAKeyGenParameterSpec(KEY_SIZE, DEFAULT_P, DEFAULT_Q);

        BigInteger exp = null;
        BigInteger d = null;

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
            generator.initialize(sraKeyGenParameterSpec);
            KeyPair keyPair = generator.generateKeyPair();
            d = ((RSAPrivateKey) keyPair.getPrivate()).getPrivateExponent();
            exp = ((RSAPublicKey) keyPair.getPublic()).getPublicExponent();
        } catch (Exception e) {
            fail("failed - setup failed. EEEEEK!!11");
        }

        try {
            KeyFactory factory = KeyFactory.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);

            BigInteger n = DEFAULT_P.multiply(DEFAULT_Q);
            PrivateKey privateKey = factory.generatePrivate(new SRADecryptionKeySpec(DEFAULT_P, DEFAULT_Q, d, exp));
            PublicKey publicKey = factory.generatePublic(new SRAEncryptionKeySpec(n, exp));

            RSAPrivateKey priv = (RSAPrivateKey) privateKey;
            RSAPublicKey pub = (RSAPublicKey) publicKey;

            if (!(priv.getModulus().equals(n))) {
                fail("failed - modulus of private key is wrong.");
            }

            if (!(pub.getModulus().equals(n))) {
                fail("failed - modulus of public key is wrong.");
            }

            if (!(priv.getPrivateExponent().equals(d))) {
                fail("failed - exponent of private key is wrong.");
            }

            if (!(pub.getPublicExponent().equals(exp))) {
                fail("failed - exponent of public key is wrong.");
            }
        } catch (NoSuchAlgorithmException e) {
            fail("failed - keyfactory for sra not found", e);
        } catch (NoSuchProviderException e) {
            fail("failed - bc provider not found, e");
        } catch (InvalidKeySpecException e) {
            fail("failed - SRAKeySpec not recognized.", e);
        }
    }

    private void restorePandQFromGeneratedKeys() {
        System.out.println("restorePandQFromGeneratedKeys");
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
            SRAKeyGenParameterSpec sraKeyGenParameterSpec = new SRAKeyGenParameterSpec(KEY_SIZE, DEFAULT_P, DEFAULT_Q);
            generator.initialize(sraKeyGenParameterSpec);
            KeyPair keyPair = generator.generateKeyPair();

            KeyFactory factory = KeyFactory.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);

            SRADecryptionKeySpec keySpec = factory.getKeySpec(keyPair.getPrivate(), SRADecryptionKeySpec.class);

            if (!keySpec.getP().equals(DEFAULT_P)) {
                fail("failed - uncorrect p in keyspec.");
            }

            if (!keySpec.getQ().equals(DEFAULT_Q)) {
                fail("failed - uncorrect p in keyspec.");
            }

        } catch (NoSuchAlgorithmException e) {
            fail("fail");
        } catch (NoSuchProviderException e) {
            fail("fail");
        } catch (InvalidAlgorithmParameterException e) {
            fail("fail");
        } catch (InvalidKeySpecException e) {
            fail("failed - unable to recover keyspec from valid sra key.");
        }
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new SRATest());
    }

    // http://redmine.fh-wedel.de/issues/902
    private void restoreKeyAndUseIt() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        SRAKeyGenParameterSpec sraKeyGenParameterSpec = new SRAKeyGenParameterSpec(2048, DEFAULT_P, DEFAULT_Q);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(sraKeyGenParameterSpec);
        KeyPair keyPair = generator.generateKeyPair();

        KeyFactory factory = KeyFactory.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
        SRADecryptionKeySpec keySpec = factory.getKeySpec(keyPair.getPrivate(), SRADecryptionKeySpec.class);

        BigInteger d = keySpec.getD();
        BigInteger exp = keySpec.getE();

        // Create another Keypair
        BigInteger n = DEFAULT_P.multiply(DEFAULT_Q);
        PrivateKey privateKey = factory.generatePrivate(new SRADecryptionKeySpec(DEFAULT_P, DEFAULT_Q, d, exp));
        PublicKey publicKey = factory.generatePublic(new SRAEncryptionKeySpec(n, exp));

        KeyPair keyPair2 = new KeyPair(publicKey, privateKey);

        // Try encryption and decryption

        // No problems with keypair
        Cipher engine = null;
        try {
            engine = Cipher.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
            engine.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] ciphertext = engine.doFinal("Test".getBytes());
            engine.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] plaintext = engine.doFinal(ciphertext);

            if (!Arrays.areEqual(plaintext, "Test".getBytes())) {
                fail("fail - decrypton failed to restore original plain text");
            }
        } catch (Exception e) {
            fail("fail - Exception using generated keypair.", e);
        }

        try {
            Cipher engine2 = Cipher.getInstance("SRA", BouncyCastleProvider.PROVIDER_NAME);
            engine2.init(Cipher.ENCRYPT_MODE, keyPair2.getPublic());
            byte[] ciphertext2 = engine2.doFinal("Test".getBytes());
            engine2.init(Cipher.DECRYPT_MODE, keyPair2.getPrivate());
            byte[] plaintext2 = engine2.doFinal(ciphertext2);

            if (!Arrays.areEqual(plaintext2, "Test".getBytes())) {
                fail("fail - decrypton failed to restore original plain text");
            }
        } catch (Exception e) {
            fail("fail - Exception using restored keypair.", e);
        }
    }
}
