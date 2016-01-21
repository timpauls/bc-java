## SRA-Implementation

### Bounce-Castle Internal

**org.bouncycastle.crypto.engines.SRAEngine**

The SRAEngine is just an RSAEngine-Wrapper. It just corrects the exception-messages thrown from the RSAEngine.


**org.bouncycastle.crypto.engines.SRABlindedEngine**

The SRABlindedEngine is just an RSABlindedEngine-Wrapper. It just corrects the exception-messages thrown from the RSABlindedEngine.

**org.bouncycastle.crypto.params.SRAKeyPairParameters**

Holds information about SRA keys: p, q, e and d


**org.bouncycastle.crypto.util.SRAKeyParameterExtractor**

Extracts SRAKeyPairParameters from a passed SRA keypair.


**org.bouncycastle.crypto.generators.SRAKeyPairGenerator**

The SRAKeyPairGenerator uses SRAKeyGenerationParameters to generate a Bouncy-Castle RSA key-pair, suitable for SRA use.
The primes "q" and "p" are provided by the SRAKeyGenerationParameters. It generates an "e" meeting the following requirements, according to the RSA requirements:

1. e > 1
2. e < phi(n)

It also generates "d" according to the RSA requirements met in the BC-RSA implementation (in RSAKeyPairGenerator).

SRAKeyPairGenerator can also be used to create (restore) a key pair from full information (in form of SRAKeyParameters) about it.


**org.bouncycastle.crypto.generators.SRAKeyParametersGenerator**

The SRAKeyParametersGenerator is used to generate valid SRAKeyGenerationParameters.
It generates them according to a given BIT_SIZE of "n". One also has to provide a SecureRandom-RNG and a certainty, used for prime generation.


The generated "p" and "q" fullfil the following criteria:

1. p and q are not too close together or equal (copied from BC-RSA RSAKeyPairGenerator)
2. n (computed of p and q) has a minimum weight of the NAF representation (copied from BC-RSA RSAKeyPairGenerator)
3. p and q are both prime.


**org.bouncycastle.crypto.params.SRAKeyGenerationParameters**
SRAKeyGenerationParameters provide all data needed to generate a valid key-pair for SRA purposes.
These are:
1. BIT_SIZE of the modulus
2. p and q (primes)

The SRAKeyGenerationParameters constructor checks for the following criteria:

1. p and q are not too close together or equal (copied from BC-RSA RSAKeyPairGenerator)
2. n (computed of p and q) has a minimum weight of the NAF representation (copied from BC-RSA RSAKeyPairGenerator)
3. p and q are both prime.

So all successfully constructed SRAKeyGenerationParameters are valid.

### JCE Support

SRA in Bouncy Castle can be used with the Java Cryptography Extension (JCE).
It has been added to the BouncyCastleProvider ASYMMETRIC_CIPHERS.

In order to make that work, several classes were added to the package **org.bouncycastle.jcajce.provider.asymmetric** found in the 'prov' module:

**SRA**

Main class used by BouncyCastleProvider. Based on equivalent RSA class, but contains fewer algorithms since they have already been defined in RSA.
Contains mappings for the SRA cipher including several common paddings, the SRA key pair generator and the SRA key factory.

**.sra.CipherSpi**

Largely taken from .rsa.CipherSpi, but replaced all occurrences of RSA engines with SRA engines.

**.sra.KeyPairGeneratorSpi**

Implementation of java.security.KeyPairGenerator for generating new SRA key pairs using SRAKeyPairGenerator. In keeping with the abstract class provided by the Java security API we created a spec for SRA key pair generation parameters: **.sra.SRAKeyGenParameterSpec**. This is the equivalent of java.security.spec.RSAKeyGenParameterSpec.

**.sra.KeyFactorySpi**

Implementation of java.security.KeyFactorySpi for generating complete SRA key pairs from spec (including the otherwise generated exponents e and d). Key translation from other SRA key implementations if not supported, because there have been no implementations until now. There are two new specs for SRA keys: **.sra.SRAEncryptionKeySpec** as a counterpart to java.security.spec.RSAPublicKeySpec and **.sra.SRADecryptionKeySpec** as a counterpart to java.security.spec.RSAPrivateKeySpec.


### Testing

We provide minor regressiontests for both, internal SRA and JCE-SRA support.

The internal SRA regressiontests can be found in the SRATest class in the "crypto" module.
It is also added to the RegressionTest class found in this module.
It covers:
1. Testing of KeyParameterGeneration
2. Detection of faulty parameters
3. Encryption and Decryption using SRA
4. Commutative law is met for SRA En-/Decryption.

We decided to not go into further testing, since we just re-use the already tested RSA implementation of BC.

The JCE-SRA support tests can be found in the SRATest class in the "prov" module.
It is also added to the RegressionTest class found in this module.
It covers:
1. key pair generation through JCE KeyPairGenerator
2. key pair generation provided given values for p and q through SRAKeyGenParameterSpec, including a check that the newly generated key matches the passed spec
3. key pair generation and en-/decryption with OAEP, including a check that the cipher text generated by the engine really is non-deterministic
4. key pair generation provided given values for p, q, e, d through JCE KeyFactory

We decided not to go into further testing, since the only thing that differs from RSA is the key generation.


# The Bouncy Castle Crypto Package For Java

The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms, it was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at [http://www.bouncycastle.org](http://www.bouncycastle.org).

The Legion also gratefully acknowledges the contributions made to this package by others (see [here](http://www.bouncycastle.org/contributors.html) for the current list). If you would like to contribute to our efforts please feel free to get in touch with us or visit our [donations page](https://www.bouncycastle.org/donate), sponsor some specific work, or purchase a support contract through [Crypto Workshop](http://www.cryptoworkshop.com).

The package is organised so that it contains a light-weight API suitable for use in any environment (including the newly released J2ME) with the additional infrastructure to conform the algorithms to the JCE framework.

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](http://www.bouncycastle.org/licence.html). The OpenPGP library also includes a modified BZIP2 library which is licensed under the [Apache Software License, Version 2.0](http://www.apache.org/licenses/). 

**Note**: this source tree is not the FIPS version of the APIs - if you are interested in our FIPS version please contact us directly at  [office@bouncycastle.org](mailto:office@bouncycastle.org).

## Code Organisation

The clean room JCE, for use with JDK 1.1 to JDK 1.3 is in the jce/src/main/java directory.

The **core** module provides all the functionality in the ligthweight APIs.

The **prov** module provides all the JCA/JCE provider functionality.

The **pkix** module is the home for code for X.509 certificate generation and the APIs for standards that rely on ASN.1 such
as CMS, TSP, PKCS#12, OCSP, CRMF, and CMP.

The **mail** module provides an S/MIME API built on top of CMS.

The **pg** module is the home for code used to support OpenPGP.

The build scripts that come with the full distribution allow creation of the different releases by using the different source trees while excluding classes that are not appropriate and copying in the required compatibility classes from the directories containing compatibility classes appropriate for the distribution.

If you want to try create a build for yourself, using your own environment, the best way to do it is to start with the build for the distribution you are interested in, make sure that builds, and then modify your build scripts to do the required exclusions and file copies for your setup, otherwise you are likely to get class not found exceptions. The final caveat to this is that as the j2me distribution includes some compatibility classes starting in the java package, you need to use an obfuscator to change the package names before attempting to import a midlet using the BC API.


## Examples and Tests

To view some examples, look at the test programs in the packages:

*   **org.bouncycastle.crypto.test**

*   **org.bouncycastle.jce.provider.test**

*   **org.bouncycastle.cms.test**

*   **org.bouncycastle.mail.smime.test**

*   **org.bouncycastle.openpgp.test**

*   **org.bouncycastle.tsp.test**

There are also some specific example programs for dealing with SMIME and OpenPGP. They can be found in:

*   **org.bouncycastle.mail.smime.examples**

*   **org.bouncycastle.openpgp.examples**

## Mailing Lists

For those who are interested, there are 2 mailing lists for participation in this project. To subscribe use the links below and include the word subscribe in the message body. (To unsubscribe, replace **subscribe** with **unsubscribe** in the message body)

*   [announce-crypto-request@bouncycastle.org](mailto:announce-crypto-request@bouncycastle.org)  
    This mailing list is for new release announcements only, general subscribers cannot post to it.
*   [dev-crypto-request@bouncycastle.org](mailto:dev-crypto-request@bouncycastle.org)  
    This mailing list is for discussion of development of the package. This includes bugs, comments, requests for enhancements, questions about use or operation.

**NOTE:**You need to be subscribed to send mail to the above mailing list.

## Feedback 

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org), if you want to help this project survive please consider [donating](https://www.bouncycastle.org/donate).

For bug reporting/requests you can report issues here on github, via feedback-crypto if required, and we also have a [Jira issue tracker](http://www.bouncycastle.org/jira). We will accept pull requests based on this repository as well.

## Finally

Enjoy!
