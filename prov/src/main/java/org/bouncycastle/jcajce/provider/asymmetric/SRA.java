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
            provider.addAlgorithm("Cipher.SRA", PREFIX + "CipherSpi$NoPadding");
            provider.addAlgorithm("Cipher.SRA/RAW", PREFIX + "CipherSpi$NoPadding");
            provider.addAlgorithm("Cipher.SRA/PKCS1", PREFIX + "CipherSpi$PKCS1v1_5Padding");
//            provider.addAlgorithm("Cipher", PKCSObjectIdentifiers.rsaEncryption, PREFIX + "CipherSpi$PKCS1v1_5Padding");
//            provider.addAlgorithm("Cipher", X509ObjectIdentifiers.id_ea_rsa, PREFIX + "CipherSpi$PKCS1v1_5Padding");
            provider.addAlgorithm("Cipher.SRA/1", PREFIX + "CipherSpi$PKCS1v1_5Padding_PrivateOnly");
            provider.addAlgorithm("Cipher.SRA/2", PREFIX + "CipherSpi$PKCS1v1_5Padding_PublicOnly");
            provider.addAlgorithm("Cipher.SRA/OAEP", PREFIX + "CipherSpi$OAEPPadding");
//            provider.addAlgorithm("Cipher", PKCSObjectIdentifiers.id_RSAES_OAEP, PREFIX + "CipherSpi$OAEPPadding");
            provider.addAlgorithm("Cipher.SRA/ISO9796-1", PREFIX + "CipherSpi$ISO9796d1Padding");

            provider.addAlgorithm("Alg.Alias.Cipher.SRA//RAW", "SRA");
            provider.addAlgorithm("Alg.Alias.Cipher.SRA//NOPADDING", "SRA");
            provider.addAlgorithm("Alg.Alias.Cipher.SRA//PKCS1PADDING", "SRA/PKCS1");
            provider.addAlgorithm("Alg.Alias.Cipher.SRA//OAEPPADDING", "SRA/OAEP");
            provider.addAlgorithm("Alg.Alias.Cipher.SRA//ISO9796-1PADDING", "SRA/ISO9796-1");


            provider.addAlgorithm("KeyPairGenerator.SRA", PREFIX + "KeyPairGeneratorSpi");
            provider.addAlgorithm("KeyFactory.SRA", PREFIX + "KeyFactorySpi");
        }

    }
}
