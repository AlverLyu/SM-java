import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class SM2
{
    private ECDomainParameters domain;

    public SM2()
    {
        BigInteger SM2_ECC_P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",16);
        BigInteger SM2_ECC_A = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",16);
        BigInteger SM2_ECC_B = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",16);
        BigInteger SM2_ECC_N = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",16);
        BigInteger SM2_ECC_GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",16);
        BigInteger SM2_ECC_GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",16);

        ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B);

        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        domain = new ECDomainParameters(curve, g, SM2_ECC_N);
    }
    
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        ECKeyGenerationParameters keyGenerationParams = new ECKeyGenerationParameters(domain, null);
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

        keyPairGenerator.init(keyGenerationParams);
        AsymmetricCipherKeyPair kp = keyPairGenerator.generateKeyPair();

        //ECPublicKeyParameters ecPub = (ECPublicKeyParameters)kp.getPublic();
        //ECPrivateKeyParameters ecPriv = (ECPrivateKeyParameters)kp.getPrivate();

        return kp;
    }

    public byte[] serializePublicKey(ECPublicKeyParameters pubKey, boolean compress)
    {
        return pubKey.getQ().getEncoded(compress);
    }

    public ECPublicKeyParameters parsePublicKey(byte[] buf)
    {
        ECPoint pt = domain.getCurve().decodePoint(buf);
        return new ECPublicKeyParameters(pt, domain);
    }

    public byte[] serializePrivateKey(ECPrivateKeyParameters privKey)
    {
        return privKey.getD().toByteArray();
    }

    public ECPrivateKeyParameters parsePrivateKey(byte[] buf)
    {
        return new ECPrivateKeyParameters(new BigInteger(buf), domain);
    }

    public byte[][] sign(byte[] msg, ECPrivateKeyParameters privateKey)
    {
        return sign(msg, privateKey, null);
    }

    public byte[][] sign(byte[] msg, ECPrivateKeyParameters privateKey,  String userID)
    {
        byte[] id = Strings.toByteArray("1234567812345678");
        if (userID != null) {
            id = Strings.toByteArray(userID);
        }

        SM2Signer signer = new SM2Signer();
        signer.init(true, new ParametersWithID(privateKey, id));
        
        BigInteger[] signature = signer.generateSignature(msg);
        byte[][] ret = new byte[2][];
        ret[0] = signature[0].toByteArray();
        ret[1] = signature[1].toByteArray();
        return ret;
    }

    public boolean verify(byte[] msg, ECPublicKeyParameters publicKey, BigInteger r, BigInteger s)
    {
        return verify(msg, publicKey, "1234567812345678", r, s);
    }

    public boolean verify(byte[] msg, ECPublicKeyParameters publicKey, String userID, BigInteger r, BigInteger s)
    {
        SM2Signer signer = new SM2Signer();
        signer.init(false, new ParametersWithID(publicKey, Strings.toByteArray(userID)));
        return signer.verifySignature(msg, r, s);
    }

    private void demoKey()
    {
        System.out.println("Test generate key pair");
        AsymmetricCipherKeyPair key = generateKeyPair();
        ECPublicKeyParameters pub = (ECPublicKeyParameters)key.getPublic();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)key.getPrivate();
        System.out.println("Public key:");
        System.out.println(pub.getQ().getAffineXCoord().toString());
        System.out.println(pub.getQ().getAffineYCoord().toString());
        System.out.println("Private key:");
        System.out.printf("%x\n", priv.getD());
    }

    private void demoSign()
    {
        System.out.println("Test sign");
        BigInteger bi = new BigInteger("a02758f98cc7e0253e337e2a51b14627780c838934d86c03de72a", 16);
        ECPrivateKeyParameters ecPriv = new ECPrivateKeyParameters(bi, domain);

        byte[][] rs = sign(Strings.toByteArray("abc"), ecPriv);

        System.out.println( Hex.toHexString(rs[0]));
        System.out.println( Hex.toHexString(rs[1]));

    }

    private void demoVerify()
    {
        System.out.println("Test verify");
        BigInteger pubX = new BigInteger("1e6c04bbbe130169d9c7670ef839f7593e6b363e39016e334d43a9e111aca5b7", 16);
        BigInteger pubY = new BigInteger("80f83a16ac0a68fd8fbccce196c64b9fc78bbc5dbf5ccc99ed02300994c60f4", 16);

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(domain.getCurve().createPoint(pubX, pubY), domain);

        BigInteger r = new BigInteger("70634fae18c5b5171bc7916c7b905fd5b730badb99242b237c679de37a3273fc", 16);
        BigInteger s = new BigInteger("d6c80a53107b52a36504e3228280c9ee75a3b3c188714710853e55b1b9607dd3", 16);

        if (verify(Strings.toByteArray("abc"), pubKey, r, s)) {
            System.out.println("OK");
        } else {
            System.out.println("FAIL");
        }
    }

    public static void main(String[] args)
    {
        SM2 sm2 = new SM2();
        sm2.demoKey();
        sm2.demoSign();
        sm2.demoVerify();
    }
}
