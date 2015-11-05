package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

// TODO: SRA KeyFactory
// research:
// the bc BaseKeyFactorySpi class does many things we appearantly won't need for sra imo.
// it's maybe more clever to just extend the KeyFactorySpi.class from java.security
// that's all we need to fulfill the requirements as far as i can see.
// first thought: all we need for this, are SRAKeySpecs for private and public key.
// rest should be given, since we use RSA as a black box.
public class SRA
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".sra.";

    public static class Mappings extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyPairGenerator.SRA", PREFIX + "KeyPairGeneratorSpi");
            provider.addAlgorithm("Cipher.SRA", PREFIX + "CipherSpi$NoPadding");
            //provider.addAlgorithm("KeyFactory.SRA", PREFIX + "KeyFactorySpi");
        }

    }
}
