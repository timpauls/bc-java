package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.DataLengthException;

/**
 * this does your basic SRA algorithm.
 * SRA is just RSA with public p and q, but secret e
 */
public class SRAEngine extends RSAEngine {
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
