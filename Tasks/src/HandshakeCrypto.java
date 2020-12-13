import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
    /**
     *
     * @param plaintext The plain text that is to be encrypted.
     * @param key The public key that is used to encrypt the text.
     * @return Returns the encrypted text as a byte array.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.update(plaintext);
        return cipher.doFinal();
    }

    /**
     *
     * @param ciphertext The cipher text that is to be decrypted.
     * @param key The private key used to decrypt the cipher text.
     * @return Returns the decrypted text as a byte array.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        cipher.update(ciphertext);
        return cipher.doFinal();
    }

    /**
     *
     * @param certfile The file path to the certificate file
     * @return Returns the public key from the certificate as a PublicKey object
     * @throws CertificateException
     * @throws IOException
     */
    public static PublicKey getPublicKeyFromCertFile(String certfile) throws CertificateException, IOException {
        String certContent = new String(Files.readAllBytes(Paths.get(certfile)), StandardCharsets.UTF_8);
        byte[] certByte = certContent.getBytes();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certByte);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
        return cert.getPublicKey();
    }

    /**
     *
     * @param keyfile The file path to the key file. Must be a pkcs8 format (.der-file)
     * @return Returns a PrivateKey object from the key-file.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] privKeyByteArray = Files.readAllBytes(Paths.get(keyfile));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }
}
