import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionDecrypter {
    private Cipher cipher;

    public SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(keybytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivbytes);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    }

    public CipherInputStream openCipherInputStream(InputStream input){
        return new CipherInputStream(input, cipher);
    }
}
