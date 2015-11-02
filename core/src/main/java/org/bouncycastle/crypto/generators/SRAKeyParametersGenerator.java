package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SRAKeyParametersGenerator
{
    private int             size;
    private int             certainty;
    private SecureRandom    random;

    private static final BigInteger TWO = BigInteger.valueOf(2);

    /**
     * Initialise the parameters generator.
     * 
     * @param size bit length for the prime p
     * @param certainty level of certainty for the prime number tests
     * @param random  a source of randomness
     */
    public void init(
        int             size,
        int             certainty,
        SecureRandom    random)
    {
        this.size = size;
        this.certainty = certainty;
        this.random = random;
    }

    /**
     * which generates the p and q values from the given parameters,
     * returning the SRAKeyGenerationParameters object.
     * <p>
     * Note: can take a while...
     */
    public SRAKeyGenerationParameters generateParameters()
    {
        while (true) {
            BigInteger p;
            while (true) {
                p = new BigInteger(this.size / 2, this.certainty, this.random);

                if (p.isProbablePrime(this.certainty)) {
                    break;
                }
            }

            BigInteger q;
            while (true) {
                q = new BigInteger(this.size / 2, this.certainty, this.random);

                if (q.isProbablePrime(this.certainty)) {
                    break;
                }
            }

            BigInteger n = p.multiply(q);
            if (n.bitLength() == this.size) {
                return new SRAKeyGenerationParameters(p, q, this.random, this.size, this.certainty);
            }

        }
    }
}
