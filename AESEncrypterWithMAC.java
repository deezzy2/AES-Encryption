import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

public class AESEncrypterWithMAC {
    public static final int IV_SIZE = 16; // 128 bits
    public static final int KEY_SIZE = 16; // 128 bits
    public static final int BUFFER_SIZE = 1024; // 1KB

    Cipher cipher;
    SecretKey secretKey;
    AlgorithmParameterSpec ivSpec;
    byte[] buf = new byte[BUFFER_SIZE];
    byte[] ivBytes = new byte[IV_SIZE];

    public AESEncrypterWithMAC(SecretKey key) throws Exception {
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        secretKey = key;
    }

    public void encrypt(InputStream in, OutputStream out) throws Exception {
        ivBytes = createRandBytes(IV_SIZE);
        out.write(ivBytes);
        ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        CipherOutputStream cipherOut = new CipherOutputStream(out, cipher);
        int numRead = 0;
        while ((numRead = in.read(buf)) >= 0) {
            cipherOut.write(buf, 0, numRead);
        }
        cipherOut.close();
    }

    public void decrypt(InputStream in, OutputStream out) throws Exception {
        // read IV first
        in.read(ivBytes);
        ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        try (// Bytes read from in will be decrypted
                CipherInputStream cipherIn = new CipherInputStream(in, cipher)) {
            // Read in the decrypted bytes and write the plaintext to out
            int numRead = 0;
            while ((numRead = cipherIn.read(buf)) >= 0)
                out.write(buf, 0, numRead);
        }
        out.close();
    }

    public static byte[] createRandBytes(int numBytes)
            throws NoSuchAlgorithmException {
        byte[] bytesBuffer = new byte[numBytes];
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.nextBytes(bytesBuffer);
        return bytesBuffer;
    }

    public static void main(String[] args) throws Exception {
        // 1. Generate a 256-bit AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // 2. Generate a 256-bit HMAC-SHA256 key
        KeyGenerator hmacKeyGen = KeyGenerator.getInstance("HmacSHA256");
        hmacKeyGen.init(256);
        SecretKey hmacKey = hmacKeyGen.generateKey();

        // 3. Encrypt the file
        AESEncrypter encrypter = new AESEncrypter(key);
        FileInputStream in = new FileInputStream("input.txt");
        FileOutputStream out = new FileOutputStream("input.txt.enc");
        encrypter.encrypt(in, out);
        in.close();
        out.close();

        // 4. Compute the HMAC-SHA256
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        in = new FileInputStream("input.txt.enc");
        byte[] hmac = mac.doFinal(in.readAllBytes());
        in.close();

        // 5. Write the HMAC-SHA256 to a file
        out = new FileOutputStream("input.txt.hmac");
        out.write(hmac);
        out.close();

        // 7. Read the HMAC-SHA256 from a file
        in = new FileInputStream("input.txt.hmac");
        byte[] hmac2 = in.readAllBytes();
        in.close();

        // 8. Verify the HMAC-SHA256
        mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        in = new FileInputStream("input.txt.enc");
        byte[] hmac3 = mac.doFinal(in.readAllBytes());
        in.close();
        if (MessageDigest.isEqual(hmac2, hmac3)) {
            System.out.println("HMAC-SHA256 verified");
            // 9. Decrypt the file
            AESEncrypter decrypter = new AESEncrypter(key);
            in = new FileInputStream("input.txt.enc");
            out = new FileOutputStream("input.txt.dec");
            decrypter.decrypt(in, out);
            in.close();
            out.close();

        } else
            System.out.println("HMAC-SHA256 verification failed");
    }

}