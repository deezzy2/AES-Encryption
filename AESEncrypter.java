import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

public class AESEncrypter {
public static final int IV_SIZE = 16; // 128 bits
public static final int KEY_SIZE = 16; // 128 bits
public static final int BUFFER_SIZE = 1024; // 1KB

Cipher cipher;
SecretKey secretKey;
AlgorithmParameterSpec ivSpec;
byte[] buf = new byte[BUFFER_SIZE];
byte[] ivBytes = new byte[IV_SIZE];

public AESEncrypter(SecretKey key) throws Exception {
cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
secretKey = key;
}

public void encrypt(InputStream in, OutputStream out) throws Exception {
// create IV and write to output
ivBytes = createRandBytes(IV_SIZE);
out.write(ivBytes);
ivSpec = new IvParameterSpec(ivBytes);
cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
// Bytes written to cipherOut will be encrypted
CipherOutputStream cipherOut = new CipherOutputStream(out, cipher);
// Read in the cleartext bytes and write to cipherOut to encrypt
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
// Bytes read from in will be decrypted
CipherInputStream cipherIn = new CipherInputStream(in, cipher);
// Read in the decrypted bytes and write the plaintext to out
int numRead = 0;
while ((numRead = cipherIn.read(buf)) >= 0)
out.write(buf, 0, numRead);
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
// Create a key
SecretKey key = new SecretKeySpec(createRandBytes(KEY_SIZE), "AES");
// Create encrypter/decrypter class
AESEncrypter encrypter = new AESEncrypter(key);
// Encrypt
FileInputStream in = new FileInputStream("input.txt");
FileOutputStream out = new FileOutputStream("input.txt.enc");
encrypter.encrypt(in, out);
in.close();
out.close();
// Decrypt
in = new FileInputStream("input.txt.enc");
out = new FileOutputStream("input.txt.dec");
encrypter.decrypt(in, out);
in.close();
out.close();
}
}