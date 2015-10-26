package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.KeyGenerationParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SRAKeyGenerationParameters extends KeyGenerationParameters {
    private BigInteger p;
    private BigInteger q;
    private int certainty;

    public SRAKeyGenerationParameters(BigInteger p, BigInteger q, SecureRandom random, int certainty)
    {
        super(random, 0); // strength is not needed for SRA
        this.p = p;
        this.q = q;
        this.certainty = certainty;

        if (!p.isProbablePrime(certainty)) {
            throw new IllegalArgumentException("p is probably NOT prime!");
        }

        if (!q.isProbablePrime(certainty)) {
            throw new IllegalArgumentException("q is probably NOT prime!");
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
