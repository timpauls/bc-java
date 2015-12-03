package org.bouncycastle.crypto.util;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.SRAKeyParameters;

public class SRAKeyParameterExtractor {
    public static SRAKeyParameters extractParameters(AsymmetricCipherKeyPair keyPair) {
        if (!(keyPair.getPublic() instanceof RSAKeyParameters)) {
            throw new IllegalArgumentException("not an sra key-pair.");
        }

        if (!(keyPair.getPrivate() instanceof RSAPrivateCrtKeyParameters)) {
            throw new IllegalArgumentException("not an sra key-pair");
        }


        RSAKeyParameters pub = (RSAKeyParameters) keyPair.getPublic();
        RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();

        if (!(pub.getModulus().equals(priv.getModulus()))) {
            throw new IllegalArgumentException("not an valid sra key-pair. modulus is different.");
        }

        return new SRAKeyParameters(priv.getP(), priv.getQ(), priv.getPublicExponent(), priv.getExponent());
    }
}
