import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SessionEncrypter {
    private SecureRandom secureRandom = new SecureRandom();
    private Cipher cipher;
    private SecretKeySpec sessionKey;
    private IvParameterSpec ivSpec;

    public SessionEncrypter(Integer keylength) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        byte[] key = new byte[keylength/8];
        secureRandom.nextBytes(key);
        //IV of AES is always 128 bits regardless of key length. With a nounce of 96 bits leaves us a counter with 128-96=32 bits
        byte[] nounce = new byte[96/8];
        secureRandom.nextBytes(nounce);
        byte[] iv = new byte[128/8];
        System.arraycopy(nounce, 0, iv, 0, nounce.length);
        sessionKey = new SecretKeySpec(key, "AES");
        ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
    }
    public SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        sessionKey = new SecretKeySpec(keybytes, "AES");
        ivSpec = new IvParameterSpec(ivbytes);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
    }

    public byte[] getKeyBytes(){
        return sessionKey.getEncoded();
    }
    public byte[] getIVBytes(){
        return ivSpec.getIV();
    }
    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        return new CipherOutputStream(output, cipher);
    }
}
