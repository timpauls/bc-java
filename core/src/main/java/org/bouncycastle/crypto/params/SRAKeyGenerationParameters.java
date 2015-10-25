package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class SRAKeyGenerationParameters {
    private BigInteger p;
    private BigInteger q;
    private BigInteger publicExponent;

    public SRAKeyGenerationParameters(BigInteger p, BigInteger q, BigInteger publicExponent)
    {
        this.p = p;
        this.q = q;
        // TODO: random generation of public exponent instead of passing it
        this.publicExponent = publicExponent;

        // TODO: security checks for p and q

        //
        // public exponent cannot be even
        //
        if (!publicExponent.testBit(0)) 
        {
                throw new IllegalArgumentException("public exponent cannot be even");
        }
    }

    public BigInteger getPublicExponent()
    {
        return publicExponent;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }
}
