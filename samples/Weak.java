// Planted weak crypto in Java, so qscan has something to find.
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;

public class Weak {
    void run() throws Exception {
        Cipher c = Cipher.getInstance("AES");              // Java default is AES/ECB: broken
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); // RSA: quantum-vulnerable
        MessageDigest d = MessageDigest.getInstance("SHA-256");   // fine, not reported
    }
}
