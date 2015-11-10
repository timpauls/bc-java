package org.bouncycastle.jcajce.provider.asymmetric.sra;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.ExtendedInvalidKeySpecException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

public class KeyFactorySpi
    extends BaseKeyFactorySpi
{
    public KeyFactorySpi()
    {
    }

    protected KeySpec engineGetKeySpec(Key key, Class spec) throws InvalidKeySpecException {
        if (spec.isAssignableFrom(SRAPublicKeySpec.class) && key instanceof RSAPublicKey) {
            RSAPublicKey k = (RSAPublicKey)key;
            return new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent());
        } else if (spec.isAssignableFrom(SRAPrivateKeySpec.class) && key instanceof java.security.interfaces.RSAPrivateKey) {
            java.security.interfaces.RSAPrivateKey k = (java.security.interfaces.RSAPrivateKey)key;
            return new RSAPrivateKeySpec(k.getModulus(), k.getPrivateExponent());
        }

        // TODO: super call needed?
        return super.engineGetKeySpec(key, spec);
    }

    // TODO: Instance checks to RSA really correct?
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof RSAPublicKey) {
            return new BCRSAPublicKey(new RSAKeyParameters(false, BigInteger.ONE, BigInteger.ONE));
        }
        else if (key instanceof java.security.interfaces.RSAPrivateKey) {
            return new BCRSAPrivateKey(new RSAKeyParameters(true, BigInteger.ONE, BigInteger.ONE));
        }

        throw new InvalidKeyException("key type unknown");
    }

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            throw new ExtendedInvalidKeySpecException("not yet implemented.", new RuntimeException());
        } else if (keySpec instanceof RSAPrivateKeySpec) {
            //TODO: fill with correct values.
            return new BCRSAPrivateKey(new RSAKeyParameters(false, BigInteger.ONE, BigInteger.ONE));
        }

        throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
    }

    protected PublicKey engineGeneratePublic (KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof SRAPublicKeySpec) {
            // TODO: fill with correct values.
            return new BCRSAPublicKey(new RSAKeyParameters(true, BigInteger.ONE, BigInteger.ONE));
        }

        // TODO: super call needed?
        return super.engineGeneratePublic(keySpec);
    }

    //TODO: introduce SRA algOid. not needed atm.
    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo) throws IOException {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        throw new IOException("algorithm identifier " + algOid + " in key not recognised");
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo) throws IOException {
        ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();
        throw new IOException("algorithm identifier " + algOid + " in key not recognised");
    }
}
