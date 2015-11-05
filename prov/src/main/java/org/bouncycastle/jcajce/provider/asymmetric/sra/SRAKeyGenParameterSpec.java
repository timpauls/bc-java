package org.bouncycastle.jcajce.provider.asymmetric.sra;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class SRAKeyGenParameterSpec implements AlgorithmParameterSpec {
    private int         keysize;
    private BigInteger  p;
    private BigInteger  q;

    public SRAKeyGenParameterSpec(int keysize, BigInteger p, BigInteger q)
    {
        this.keysize = keysize;
        this.p = p;
        this.q = q;
    }

    public int getKeysize()
    {
        return keysize;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }
}
