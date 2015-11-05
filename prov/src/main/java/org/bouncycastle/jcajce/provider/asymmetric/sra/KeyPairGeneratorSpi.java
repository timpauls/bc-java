package org.bouncycastle.jcajce.provider.asymmetric.sra;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class KeyPairGeneratorSpi
        extends java.security.KeyPairGenerator {
    public KeyPairGeneratorSpi(String algorithmName) {
        super(algorithmName);
    }

    final static BigInteger defaultP = new BigInteger("f2ac535b14a36b3707988f789d2ffd9d407e2ce1c387382678bf33932ebf708d067f2b2425704ddb7b708d51f94c7ee5868db43acc2649d611f71f5f4acd69b1b136fde10b5c4f70fe5f3a201aa2fdb79add4065d82bcc6460d8dac58906b4a856cb57317500c176ab8af9aa9e5f667c458c9ab70837f2f06bd1d2c2f1b7b50d", 16);
    final static BigInteger defaultQ = new BigInteger("c4f0f0d53e216ce3d8ccef361026b88bd07a14985a81d74772937f1b2be85e22b24dbf41f7e7a62232f7254f090b20f23d1dcb47a18e7438756e43c62b12b611c95f0cb0b7cc03dbd6c08601240857b09247b66fc420ab80e934a8e3bd17fafa233defbbad61cd27f98dda348f72a0f7d21309e16d1c69b235b8f149a3b637df", 16);
    final static int defaultTests = 112;

    SRAKeyGenerationParameters param;
    SRAKeyPairGenerator engine;

    public KeyPairGeneratorSpi() {
        super("SRA");

        engine = new SRAKeyPairGenerator();
        param = new SRAKeyGenerationParameters(defaultP, defaultQ, new SecureRandom(), 2048, defaultTests);
        engine.init(param);
    }

    public void initialize(int strength, SecureRandom random) {
        param = new SRAKeyGenerationParameters(defaultP, defaultQ, random, strength, defaultTests);

        engine.init(param);
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof SRAKeyGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a SRAKeyGenParameterSpec");
        }
        SRAKeyGenParameterSpec sraParams = (SRAKeyGenParameterSpec) params;

        param = new SRAKeyGenerationParameters(
                sraParams.getP(),
                sraParams.getQ(),
                random, sraParams.getKeysize(), defaultTests);

        engine.init(param);
    }

    public KeyPair generateKeyPair() {
        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        RSAKeyParameters pub = (RSAKeyParameters) pair.getPublic();
        RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) pair.getPrivate();

        return new KeyPair(new BCRSAPublicKey(pub), new BCRSAPrivateCrtKey(priv));
    }
}
