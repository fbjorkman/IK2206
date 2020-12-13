import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class SessionKey {

    private SecretKey key;

    public SessionKey(Integer keylength){
        try {
            //Key length for AES has to be 128, 192 or 256
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(keylength);
            key = keygen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    public SessionKey(byte[] keybytes){
        key = new SecretKeySpec(keybytes, 0, keybytes.length, "AES");
    }

    protected byte[] getKeyBytes(){
        return key.getEncoded();
    }
    protected SecretKey getSecretKey(){
        return key;
    }
}
