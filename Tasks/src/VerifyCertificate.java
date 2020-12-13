import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class VerifyCertificate {
    /**
     *
     * @param args Takes two arguments. First argument needs to be the certificate for the CA and
     *             the second argument needs to be the certificate for the user
     * @throws IOException
     * @throws CertificateException
     */
    public static void main(String[] args) throws IOException, CertificateException {
        Certificate tempCA = null;
        Certificate tempUser = null;
        X509Certificate ca;
        X509Certificate user;

        if(args.length != 2){
            System.out.println("You need two paths to certificates as arguments to run this program");
        }
        else{
            FileInputStream inStreamCA = new FileInputStream(String.valueOf(Paths.get(args[0])));
            FileInputStream inStreamUser = new FileInputStream(String.valueOf(Paths.get(args[1])));
            BufferedInputStream bisCA = new BufferedInputStream(inStreamCA);
            BufferedInputStream bisUser = new BufferedInputStream(inStreamUser);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            while (bisCA.available() > 0){
                tempCA = cf.generateCertificate(bisCA);
            }
            while (bisUser.available() > 0){
                tempUser = cf.generateCertificate(bisUser);
            }
            ca = (X509Certificate) tempCA;
            user = (X509Certificate) tempUser;

            System.out.println("DN of the CA: " + ca.getSubjectDN());
            System.out.println("DN of the User: " + user.getSubjectDN());

            try{
                ca.verify(ca.getPublicKey());
                ca.checkValidity();
                user.verify(ca.getPublicKey());
                user.checkValidity();
                System.out.println("Pass");
            }
            catch (NoSuchAlgorithmException e) {
                System.out.println("Fail:");
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                System.out.println("Fail:");
                e.printStackTrace();
            } catch (SignatureException e) {
                System.out.println("Fail:");
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                System.out.println("Fail:");
                e.printStackTrace();
            }
        }
    }
}
