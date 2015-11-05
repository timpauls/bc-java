package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

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
        }

    }
}
