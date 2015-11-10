package org.bouncycastle.jcajce.provider.asymmetric.sra;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class SRADecryptionKeySpec implements KeySpec{
    private BigInteger n;
    private BigInteger d;

    public SRADecryptionKeySpec(BigInteger n, BigInteger d) {
        this.n = n;
        this.d = d;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getD() {
        return d;
    }
}
