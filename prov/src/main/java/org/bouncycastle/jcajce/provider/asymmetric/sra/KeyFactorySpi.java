package org.bouncycastle.jcajce.provider.asymmetric.sra;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.ExtendedInvalidKeySpecException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class KeyFactorySpi extends BaseKeyFactorySpi {
    public KeyFactorySpi() {
    }

    protected KeySpec engineGetKeySpec(Key key, Class spec) throws InvalidKeySpecException {
        if (spec.isAssignableFrom(SRAEncryptionKeySpec.class) && key instanceof RSAPublicKey) {
            RSAPublicKey k = (RSAPublicKey) key;
            return new SRAEncryptionKeySpec(k.getModulus(), k.getPublicExponent());
        } else if (spec.isAssignableFrom(SRADecryptionKeySpec.class) && key instanceof java.security.interfaces.RSAPrivateKey) {
            java.security.interfaces.RSAPrivateKey k = (java.security.interfaces.RSAPrivateKey) key;
            return new SRADecryptionKeySpec(k.getModulus(), k.getPrivateExponent());
        }

        throw new InvalidKeySpecException("not implemented yet " + key + " " + spec);
    }

    // TODO: do we need it?
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        throw new InvalidKeyException("key type unknown");
    }

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            throw new ExtendedInvalidKeySpecException("not yet implemented.", new RuntimeException());
        } else if (keySpec instanceof SRADecryptionKeySpec) {
            SRADecryptionKeySpec spec = (SRADecryptionKeySpec) keySpec;
            return new BCRSAPrivateKey(new RSAKeyParameters(true, spec.getN(), spec.getD()));
        }

        throw new InvalidKeySpecException("Unknown KeySpec type: " + keySpec.getClass().getName());
    }

    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof SRAEncryptionKeySpec) {
            SRAEncryptionKeySpec spec = (SRAEncryptionKeySpec) keySpec;
            return new BCRSAPublicKey(new RSAKeyParameters(false, spec.getN(), spec.getE()));
        }

        throw new InvalidKeySpecException("key spec not recognised");
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
