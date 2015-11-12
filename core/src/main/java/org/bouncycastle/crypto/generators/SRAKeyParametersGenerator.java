package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.math.ec.WNafUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SRAKeyParametersGenerator
{
    private int             size;
    private int             certainty;
    private SecureRandom    random;

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
        int mindiffbits = this.size / 3;
        int minWeight = this.size >> 2;

        while (true) {
            BigInteger p;
            while (true) {
                p = new BigInteger(this.size / 2, this.certainty, this.random);

                if (p.isProbablePrime(this.certainty)) {
                    break;
                }
//                System.out.println("Generation new p...");
            }

            BigInteger q;
            while (true) {
                q = new BigInteger(this.size / 2, this.certainty, this.random);

                if (q.isProbablePrime(this.certainty) && !q.equals(p)) {
                    break;
                }
//                System.out.println("Generation new q...");
            }


            // p and q should not be too close together (or equal!)
            BigInteger diff = q.subtract(p).abs();
            if (diff.bitLength() < mindiffbits) {
//              System.out.println("p and q too close together or equal.");
                continue;
            }

            // modulus has to be strong enough.
            BigInteger n = p.multiply(q);

            /*
             * Require a minimum weight of the NAF representation, since low-weight composites may
             * be weak against a version of the number-field-sieve for factoring.
             *
             * See "The number field sieve for integers of low weight", Oliver Schirokauer.
             */
            if (WNafUtil.getNafWeight(n) < minWeight) {
//                System.out.println("Minimum weight NAF representation criterion not met.");
                continue;
            }

            if (n.bitLength() == this.size) {
                return new SRAKeyGenerationParameters(p, q, this.random, this.size, this.certainty);
            }

//            System.out.println("n bits: " + n.bitLength() + "; size: " + this.size);
        }
    }
}
