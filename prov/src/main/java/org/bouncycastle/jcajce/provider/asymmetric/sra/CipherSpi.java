package org.bouncycastle.jcajce.provider.asymmetric.sra;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Strings;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;

public class CipherSpi extends BaseCipherSpi {
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private AsymmetricBlockCipher cipher;
    private AlgorithmParameterSpec paramSpec;
    private AlgorithmParameters engineParams;
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    public CipherSpi(AsymmetricBlockCipher engine) {
        cipher = engine;
    }

    protected int engineGetBlockSize() {
        try {
            return cipher.getInputBlockSize();
        } catch (NullPointerException e) {
            throw new IllegalStateException("SRA Cipher not initialised");
        }
    }

    protected int engineGetKeySize(Key key) {
        if (key instanceof RSAPrivateKey) {
            RSAPrivateKey k = (RSAPrivateKey) key;

            return k.getModulus().bitLength();
        } else if (key instanceof RSAPublicKey) {
            RSAPublicKey k = (RSAPublicKey) key;

            return k.getModulus().bitLength();
        }

        throw new IllegalArgumentException("not an SRA key!");
    }

    protected int engineGetOutputSize(int inputLen) {
        try {
            return cipher.getOutputBlockSize();
        } catch (NullPointerException e) {
            throw new IllegalStateException("RSA Cipher not initialised");
        }
    }

    protected AlgorithmParameters engineGetParameters() {
        if (engineParams == null) {
            if (paramSpec != null) {
                try {
                    engineParams = helper.createAlgorithmParameters("OAEP");
                    engineParams.init(paramSpec);
                } catch (Exception e) {
                    throw new RuntimeException(e.toString());
                }
            }
        }

        return engineParams;
    }

    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        String pad = Strings.toUpperCase(padding);

        if (pad.equals("NOPADDING")) {
            cipher = new SRAEngine();
        } else {
            throw new NoSuchPaddingException(padding + " unavailable with SRA.");
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        CipherParameters param;

        if (params == null || params instanceof OAEPParameterSpec) {
            if (key instanceof RSAPublicKey) {
                param = RSAUtil.generatePublicKeyParameter((RSAPublicKey) key);
            } else if (key instanceof RSAPrivateKey) {
                param = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey) key);
            } else {
                throw new InvalidKeyException("unknown key type passed to SRA");
            }

            if (params != null) {
                OAEPParameterSpec spec = (OAEPParameterSpec) params;

                paramSpec = params;

                if (!spec.getMGFAlgorithm().equalsIgnoreCase("MGF1") && !spec.getMGFAlgorithm().equals(PKCSObjectIdentifiers.id_mgf1.getId())) {
                    throw new InvalidAlgorithmParameterException("unknown mask generation function specified");
                }

                if (!(spec.getMGFParameters() instanceof MGF1ParameterSpec)) {
                    throw new InvalidAlgorithmParameterException("unkown MGF parameters");
                }

                Digest digest = DigestFactory.getDigest(spec.getDigestAlgorithm());

                if (digest == null) {
                    throw new InvalidAlgorithmParameterException("no match on digest algorithm: " + spec.getDigestAlgorithm());
                }

                MGF1ParameterSpec mgfParams = (MGF1ParameterSpec) spec.getMGFParameters();
                Digest mgfDigest = DigestFactory.getDigest(mgfParams.getDigestAlgorithm());

                if (mgfDigest == null) {
                    throw new InvalidAlgorithmParameterException("no match on MGF digest algorithm: " + mgfParams.getDigestAlgorithm());
                }

                cipher = new OAEPEncoding(new RSABlindedEngine(), digest, mgfDigest, ((PSource.PSpecified) spec.getPSource()).getValue());
            }
        } else {
            throw new InvalidAlgorithmParameterException("unknown parameter type: " + params.getClass().getName());
        }

        if (!(cipher instanceof SRAEngine)) {
            if (random != null) {
                param = new ParametersWithRandom(param, random);
            } else {
                param = new ParametersWithRandom(param, new SecureRandom());
            }
        }

        bOut.reset();

        switch (opmode) {
            case Cipher.ENCRYPT_MODE:
            case Cipher.WRAP_MODE:
                cipher.init(true, param);
                break;
            case Cipher.DECRYPT_MODE:
            case Cipher.UNWRAP_MODE:
                cipher.init(false, param);
                break;
            default:
                throw new InvalidParameterException("unknown opmode " + opmode + " passed to SRA");
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec paramSpec = null;

        if (params != null) {
            try {
                paramSpec = params.getParameterSpec(OAEPParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException("cannot recognise parameters: " + e.toString(), e);
            }
        }

        engineParams = params;
        engineInit(opmode, key, paramSpec, random);
    }

    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            // this shouldn't happen
            throw new InvalidKeyException("Eeeek! " + e.toString(), e);
        }
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        bOut.write(input, inputOffset, inputLen);

        if (bOut.size() > cipher.getInputBlockSize()) {
            throw new ArrayIndexOutOfBoundsException("too much data for SRA block");
        }

        return null;
    }

    protected int engineUpdate(
            byte[] input,
            int inputOffset,
            int inputLen,
            byte[] output,
            int outputOffset) {
        bOut.write(input, inputOffset, inputLen);

        if (bOut.size() > cipher.getInputBlockSize()) {
            throw new ArrayIndexOutOfBoundsException("too much data for SRA block");
        }

        return 0;
    }

    protected byte[] engineDoFinal(
            byte[] input,
            int inputOffset,
            int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (input != null) {
            bOut.write(input, inputOffset, inputLen);
        }

        if (bOut.size() > cipher.getInputBlockSize()) {
            throw new ArrayIndexOutOfBoundsException("too much data for SRA block");
        }

        try {
            byte[] bytes = bOut.toByteArray();

            bOut.reset();

            return cipher.processBlock(bytes, 0, bytes.length);
        } catch (InvalidCipherTextException e) {
            throw new BadPaddingException(e.getMessage());
        }
    }

    protected int engineDoFinal(
            byte[] input,
            int inputOffset,
            int inputLen,
            byte[] output,
            int outputOffset)
            throws IllegalBlockSizeException, BadPaddingException {
        if (input != null) {
            bOut.write(input, inputOffset, inputLen);
        }

        if (bOut.size() > cipher.getInputBlockSize()) {
            throw new ArrayIndexOutOfBoundsException("too much data for SRA block");
        }

        byte[] out;

        try {
            byte[] bytes = bOut.toByteArray();

            out = cipher.processBlock(bytes, 0, bytes.length);
        } catch (InvalidCipherTextException e) {
            throw new BadPaddingException(e.getMessage());
        } finally {
            bOut.reset();
        }

        for (int i = 0; i != out.length; i++) {
            output[outputOffset + i] = out[i];
        }

        return out.length;
    }

    /**
     * classes that inherit from us.
     */
    static public class NoPadding
            extends CipherSpi {
        public NoPadding() {
            super(new SRAEngine());
        }
    }
}
