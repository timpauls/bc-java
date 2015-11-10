package org.bouncycastle.jcajce.provider.asymmetric.sra;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class SRAEncryptionKeySpec implements KeySpec {
    private BigInteger n;
    private BigInteger e;

    public SRAEncryptionKeySpec(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }
}
