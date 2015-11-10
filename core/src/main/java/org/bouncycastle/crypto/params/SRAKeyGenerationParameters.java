package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.math.ec.WNafUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SRAKeyGenerationParameters extends KeyGenerationParameters {
    private BigInteger p;
    private BigInteger q;
    private int certainty;

    /**
     * Constructor for SRA key generation parameters in case p and q have already been negotiated.
     * <p>
     *     For initial generation of p and q use {@link org.bouncycastle.crypto.generators.SRAKeyParametersGenerator}.
     * </p>
     * @param p
     * @param q
     * @param random
     * @param strength
     * @param certainty
     */
    public SRAKeyGenerationParameters(BigInteger p, BigInteger q, SecureRandom random, int strength, int certainty)
    {
        super(random, strength);
        this.p = p;
        this.q = q;
        this.certainty = certainty;

        if (!p.isProbablePrime(certainty)) {
            throw new IllegalArgumentException("p is probably NOT prime!");
        }

        if (!q.isProbablePrime(certainty)) {
            throw new IllegalArgumentException("q is probably NOT prime!");
        }


        BigInteger n = p.multiply(q);
        if (n.bitLength() != strength) {
            throw new IllegalArgumentException("p and q are not strong enough!");
        }

        int mindiffbits = strength / 3;
        BigInteger diff = q.subtract(p).abs();
        if (diff.bitLength() < mindiffbits) {
            throw new IllegalArgumentException("p and q lie too close together!");
        }

        /*
         * Require a minimum weight of the NAF representation, since low-weight composites may
         * be weak against a version of the number-field-sieve for factoring.
         *
         * See "The number field sieve for integers of low weight", Oliver Schirokauer.
         */
        int minWeight = strength >> 2;
        if (WNafUtil.getNafWeight(n) < minWeight) {
            throw new IllegalArgumentException("NAF weight not high enough!");
        }
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public int getCertainty() {
        return certainty;
    }
}
