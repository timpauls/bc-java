package org.bouncycastle.jcajce.provider.asymmetric.sra;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.crypto.generators.SRAKeyParametersGenerator;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class KeyPairGeneratorSpi
        extends java.security.KeyPairGenerator {

    public static final int STRENGTH = 2048;

    public KeyPairGeneratorSpi(String algorithmName) {
        super(algorithmName);
    }

    final static int defaultTests = 112;

    private SRAKeyGenerationParameters param;
    private SRAKeyPairGenerator engine;
    private boolean initialized = false;

    public KeyPairGeneratorSpi() {
        super("SRA");

        engine = new SRAKeyPairGenerator();
    }

    public void initialize(int strength, SecureRandom random) {
        param = generateParams(strength, random);

        engine.init(param);

        initialized = true;
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

        initialized = true;
    }

    public KeyPair generateKeyPair() {
        if (!initialized) {
            param = generateParams(STRENGTH, new SecureRandom());
            engine.init(param);
            initialized = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        RSAKeyParameters pub = (RSAKeyParameters) pair.getPublic();
        RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) pair.getPrivate();

        return new KeyPair(new BCRSAPublicKey(pub), new BCRSAPrivateCrtKey(priv));
    }

    private SRAKeyGenerationParameters generateParams(int strength, SecureRandom random) {
        SRAKeyParametersGenerator sraKeyParametersGenerator = new SRAKeyParametersGenerator();
        sraKeyParametersGenerator.init(strength, defaultTests, random);
        return sraKeyParametersGenerator.generateParameters();
    }
}
