package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.KeyGenerationParameters;

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
