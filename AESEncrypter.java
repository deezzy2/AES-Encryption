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

    /*
     * Discription for the above code
     * 
     * This is the definition of an AESEncrypter class that is used for
     * encrypting different types of data using Advanced Encryption Standard (AES)
     * algorithm in Cipher Block Chaining (CBC) mode.
     * 
     * The class provides constants to define the Initialization Vector (IV) size
     * and Key size,
     * as well as a buffer size which will be used to read data in blocks.
     * It then defines a cipher object which will be used for encrypting the
     * data.
     * 
     * The secretKey variable is of type SecretKey and it stores an encryption
     * key generated by a key generator.
     * 
     * The AlgorithmParameterSpec ivSpen stores parameters for initializing or
     * reinitializing the cipher instance with its IV.
     * This variable has to be initialized before using it for
     * encryption/decryption operations.
     * 
     * The buf byte array is used to store data in memory a block at a time,
     * while the ivBytes byte array is used to store the bytes of the initialized
     * Initialization Vector.
     * 
     * The constructor takes in a parameter of type SecretKey,
     * this is then stored in secretKey variable so it can be used later by the
     * encryption process and then instantiates a Cipher object with
     * AES/CBC/PKCS5Padding parameters indicating that we are using AES algorithm
     * with Cipher Block Chaining mode and PKCS#5 padding scheme respectively.
     */

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
        /*
         * This code is an encryption method that takes input from an InputStream and
         * writes it to the OutputStream after the data has been encrypted.
         * First, it creates a random initialization vector (ivBytes) and then writes it
         * to the OutputStream.
         * An IvParameterSpec object is created using ivBytes and is then used to
         * initialize the cipher in encryption mode and with a secret key.
         * 
         * A CipherOutputStream is then created using that cipher, which reads in clear
         * text bytes from the InputStream, encrypts them,
         * and then writes them out to the OutputStream. Once all of the data has been
         * read from the InputStream and
         * written to the CipherOutput Stream, it closes all of the streams.
         */
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
        /*
         * This code is used to decrypt a stream of data that has been encrypted with
         * the specified cipher.
         * It first reads the initialization vector (IV) that was used for the
         * encryption.
         * This initialization vector is then used to initialize the Cipher, so that it
         * can properly decrypt the data with the correct key.
         * After initializing the Cipher, a CipherInputStream is created which will
         * begin decrypting data from the InputStream in and
         * writing it to an OutputStream out. The decrypted data is then read from
         * cipherIn, written to buf, and
         * ultimately written out in plaintext to out. At the end, out is closed.
         */
    }

    public static byte[] createRandBytes(int numBytes)
            throws NoSuchAlgorithmException {
        byte[] bytesBuffer = new byte[numBytes];
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.nextBytes(bytesBuffer);
        return bytesBuffer;
        /*
         * This code creates and returns an array of random bytes of a certain size.
         * It does this by creating an array called "bytesBuffer" which is of length
         * numBytes.
         * It then generates a secure random number using the SecureRandom class with
         * the SHA1 algorithm, and
         * assigns the randoms bytes to the byte array using the sr.nextBytes() method.
         * Finally it returns the array of random bytes.
         */
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
        /*
         * This code is creating and implementing encryption and decryption for a file.
         * A key is created with the createRandBytes() method that defines the size of
         * the encryption.
         * An AES Encrypter object is then created which then encrypts and decrypts the
         * file input.txt in two different files;
         * "input.txt.enc" and "input.txtdec".
         * These encrypted files keep the data safe from anyone who doesn't have the key
         * to decrypt them, thus keeping it secure.
         */
    }
}