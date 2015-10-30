package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;

import java.math.BigInteger;

/**
 * Created by tim on 25.10.2015.
 */
public class SRAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private SRAKeyGenerationParameters param;

    @Override
    public void init(KeyGenerationParameters param) {
        this.param = (SRAKeyGenerationParameters) param;
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair() {
        AsymmetricCipherKeyPair result;
        BigInteger p, q, n, d, e, pSub1, qSub1, gcd, lcm;

        p = param.getP();
        q = param.getQ();
        n = p.multiply(q);

        if (p.compareTo(q) < 0)
        {
            gcd = p;
            p = q;
            q = gcd;
        }

        pSub1 = p.subtract(ONE);
        qSub1 = q.subtract(ONE);
        gcd = pSub1.gcd(qSub1);
        lcm = pSub1.divide(gcd).multiply(qSub1);

        e = chooseRandomPublicExponent(pSub1.multiply(qSub1));

        //
        // calculate the private exponent
        //
        d = e.modInverse(lcm);

        //
        // calculate the CRT factors
        //
        BigInteger dP, dQ, qInv;

        dP = d.remainder(pSub1);
        dQ = d.remainder(qSub1);
        qInv = q.modInverse(p);

        result = new AsymmetricCipherKeyPair(
                new RSAKeyParameters(false, n, e),
                new RSAPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));

        return result;
    }

    /**
     * Choose a random public exponent to use with SRA.
     *
     * @param phiN (p-1)*(q-1)
     * @return an exponent e, with 1 < e < phiN
     */
    private BigInteger chooseRandomPublicExponent(BigInteger phiN)
    {
        for (;;)
        {
            BigInteger e = new BigInteger(phiN.bitLength(), param.getCertainty(), param.getRandom());

            if (e.compareTo(ONE) <= 0) {
                continue;
            }

            if (e.compareTo(phiN) >= 0) {
                continue;
            }

            return e;
        }
    }
}
