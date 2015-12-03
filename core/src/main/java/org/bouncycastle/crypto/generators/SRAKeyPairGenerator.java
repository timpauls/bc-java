package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SRAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SRAKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.IndexGenerator;

import java.math.BigInteger;

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

        // d lower bound is 2^(strength / 2)
        BigInteger dLowerBound = BigInteger.valueOf(2).pow(param.getStrength() / 2);

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

        boolean done = false;
        do {
            e = chooseRandomPublicExponent(pSub1.multiply(qSub1));

            //
            // calculate the private exponent
            //
            d = e.modInverse(lcm);

            done = d.compareTo(dLowerBound) > 0;

//            if (!done) {
//                System.out.println("ERROR: d too small. should be " + dLowerBound.toString(10) + " but is " + d.toString(10));
//            }
        } while (!done);

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

    public static AsymmetricCipherKeyPair createKeyPair(SRAKeyParameters parameters) {
        BigInteger n = parameters.getP().multiply(parameters.getQ());
        //
        // calculate the CRT factors
        //
        BigInteger dP, dQ, qInv;

        dP = parameters.getD().remainder(parameters.getP().subtract(ONE));
        dQ = parameters.getD().remainder(parameters.getQ().subtract(ONE));
        qInv = parameters.getQ().modInverse(parameters.getP());

        return new AsymmetricCipherKeyPair(
                new RSAKeyParameters(false, n, parameters.getE()),
                new RSAPrivateCrtKeyParameters(n, parameters.getE(), parameters.getD(), parameters.getP(), parameters.getQ(), dP, dQ, qInv));
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
            BigInteger e = new BigInteger(phiN.bitLength(), param.getRandom());
            if (!e.gcd(phiN).equals(BigInteger.ONE)) {
                continue;
            }

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
