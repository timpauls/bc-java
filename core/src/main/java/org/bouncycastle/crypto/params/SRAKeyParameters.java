package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class SRAKeyParameters {
    private BigInteger p;
    private BigInteger q;
    private BigInteger e;
    private BigInteger d;

    public SRAKeyParameters(BigInteger p, BigInteger q, BigInteger e, BigInteger d) {
        this.p = p;
        this.q = q;
        this.e = e;
        this.d = d;
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

    public BigInteger getD() {
        return d;
    }
}
