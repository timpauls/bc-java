package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * this does your basic RSA algorithm with blinding
 */
public class SRABlindedEngine extends RSABlindedEngine {
    @Override
    public byte[] processBlock(byte[] in, int inOff, int inLen) {
        try {
            return super.processBlock(in, inOff, inLen);
        } catch (IllegalStateException e) {
            throw new IllegalStateException(e.getMessage().replaceAll("RSA", "SRA"));
        } catch (DataLengthException e) {
            throw new DataLengthException(e.getMessage().replaceAll("RSA", "SRA"));
        }
    }
}
