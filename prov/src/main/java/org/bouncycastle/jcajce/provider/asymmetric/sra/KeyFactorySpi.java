package org.bouncycastle.jcajce.provider.asymmetric.sra;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
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

            RSAPrivateCrtKey k = (RSAPrivateCrtKey)key;

            RSAPrivateCrtKeyParameters parameters = new RSAPrivateCrtKeyParameters(k.getModulus(),
                    k.getPublicExponent(), k.getPrivateExponent(),
                    k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient());

            return new SRADecryptionKeySpec(parameters.getP(), parameters.getQ(), parameters.getExponent(), parameters.getPublicExponent());
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

            BigInteger pSub1 = spec.getP().subtract(BigInteger.ONE);
            BigInteger qSub1 = spec.getQ().subtract(BigInteger.ONE);

            //
            // calculate the CRT factors
            //
            BigInteger dP, dQ, qInv;

            dP = spec.getD().remainder(pSub1);
            dQ = spec.getD().remainder(qSub1);
            qInv = spec.getQ().modInverse(spec.getP());

            return new BCRSAPrivateCrtKey(new RSAPrivateCrtKeyParameters(spec.getN(), spec.getE(), spec.getD(), spec.getP(), spec.getQ(), dP, dQ, qInv));
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
