package org.bouncycastle.jcajce.provider.asymmetric.sra;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class SRADecryptionKeySpec implements KeySpec{
    private BigInteger d;
    private BigInteger p;
    private BigInteger q;
    private BigInteger e;

    public SRADecryptionKeySpec(BigInteger p, BigInteger q, BigInteger d, BigInteger e) {
        this.p = p;
        this.q = q;
        this.d = d;
        this.e = e;
    }

    public BigInteger getN() {
        return p.multiply(q);
    }

    public BigInteger getD() {
        return d;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getE() {
        return e;
    }
}
