// Students: Vincent Cordova, Jessica Nguyen


import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.KeyFactory;

public class Sender {
    // Get plaintext
    // Encrypt plaintext using random key AES-EN Kxy (M)
    // Padding ("AES/CBC/PKCS5Padding", "SunJCE")
    // Kxy is encrypted using Ky+ RSA
    // Concatenate Encrypted Data || Encrypted Kxy   

    // Number of bytes read at a time
    final private static int BUFFER_SIZE = 32 * 1024;
    // 100MB file size boundary, exceeding this terminates the program
    final private static Long FILE_SIZE_BOUNDARY = 100L * 1024 * 1024;
    
    final private static String IV = "OOGABOOGAOOGABOO";
    public static void main(String[] args) throws Exception{
        
        // Allow user to input name of plaintext file
        Scanner s = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String fileName = s.nextLine();
        
        final String MESSAGE_FILE = "message.kmk"; 
        final String SYMMETRIC_KEY_FILE = "symmetric.key";

        encrypt(SYMMETRIC_KEY_FILE, fileName);
        
        BufferedInputStream symmetricKeyReader = new BufferedInputStream(new FileInputStream(SYMMETRIC_KEY_FILE));
        
        // The resources to read message from input and write message to output
        BufferedInputStream messageReader = new BufferedInputStream(new FileInputStream(fileName));
        BufferedOutputStream messageWriter = new BufferedOutputStream(new FileOutputStream(MESSAGE_FILE, true));
        
        // A byte array to read bytes from the input file
        byte[] readBuffer = new byte[BUFFER_SIZE];
        // currentBytesRead is the chunk of byte info that is taken from the readBuffer
        int currentBytesRead;
        int keyBytesRead;
        long totalBytesRead = 0;
        
        while((keyBytesRead = symmetricKeyReader.read(readBuffer)) != -1) {
            messageWriter.write(readBuffer, 0, keyBytesRead);
        }
        
        symmetricKeyReader.close();
        while((currentBytesRead = messageReader.read(readBuffer)) != -1) {
            // Track the total bytes read to determine if the file is too large, terminate the program if so
            totalBytesRead += currentBytesRead;
            if (totalBytesRead > FILE_SIZE_BOUNDARY) System.exit(1); // exit code 1 indicates error
            messageWriter.write(readBuffer, 0, currentBytesRead);
        }
        
        messageReader.close();
        symmetricKeyReader = new BufferedInputStream(new FileInputStream(SYMMETRIC_KEY_FILE));
        while((currentBytesRead = symmetricKeyReader.read(readBuffer)) != -1) {
            messageWriter.write(readBuffer, 0, currentBytesRead);
        }
        symmetricKeyReader.close();
        messageWriter.close();
        messageDigestionSHA256(MESSAGE_FILE);
    }    
    
    
    
    public static String messageDigestionSHA256(String f) throws Exception {
        Scanner s = new Scanner(System.in);
        System.out.print("Do you want to invert the first byte?(y/n)");
        String invert = s.nextLine();
        
        BufferedInputStream bufferedReader = new BufferedInputStream(new FileInputStream(f));
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        // Do this on first read instead
        DigestInputStream in = new DigestInputStream(bufferedReader, messageDigest);
        byte[] buffer = new byte[BUFFER_SIZE];        
        
        int i;
        do {
            i = in.read(buffer, 0, BUFFER_SIZE);
        } while (i == BUFFER_SIZE);
        messageDigest = in.getMessageDigest();
        in.close();

        byte[] hash = messageDigest.digest();

        if (invert.equalsIgnoreCase("Y")) {
            hash[0] = (byte) ~hash[0]; // invert the first byte
        }

        System.out.println("Hash value: ");
        for (int k=0, j=0; k<hash.length; k++, j++) {
            System.out.format("%2X ", hash[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
        System.out.println("");
        FileOutputStream macWriter = new FileOutputStream("message.khmac");
        macWriter.write(hash);
        macWriter.close();
        s.close();
        return new String(hash);
    }

    public static void encrypt(String SYMMETRIC_KEY_FILE, String messageFile) throws Exception {
        byte[] symmetricKey = new byte[16];
        try (BufferedInputStream keyReader = new BufferedInputStream(new FileInputStream("symmetric.key"))) {
            int bytesRead = keyReader.read(symmetricKey);
            if (bytesRead != 16) {
                throw new IOException("Expected key length of 16 bytes but got " + bytesRead);
            }
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symmetricKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));

        BufferedInputStream messageReader = new BufferedInputStream(new FileInputStream(messageFile));
        BufferedOutputStream encryptionWriter = new BufferedOutputStream(new FileOutputStream("message.aescipher"));


        byte[] currentChunk = new byte[16];
        int bytesRead;

        while ((bytesRead = messageReader.read(currentChunk)) != -1) {
            // I love ternary operators
            // If bytesRead < 16 bytes, give it padding. Else, no padding.
            byte[] checkChunk = (bytesRead < currentChunk.length) ? Arrays.copyOf(currentChunk, bytesRead) : currentChunk;

            byte[] outputChunk = cipher.update(checkChunk);

            encryptionWriter.write(outputChunk);
        }

        byte[] endBytes = cipher.doFinal();
        if( endBytes != null && endBytes.length > 0) {
            encryptionWriter.write(endBytes);
        }
        encryptionWriter.close();
        messageReader.close();

        // AES stops here
        // RSA starts here

        BigInteger modulus, exponent;
        ObjectInputStream keyReader = new ObjectInputStream(new FileInputStream("YPublic.key"));
        modulus = (BigInteger)keyReader.readObject();
        exponent = (BigInteger)keyReader.readObject();

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey yPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.ENCRYPT_MODE, yPublicKey);
        byte[] encryptedKxy = cipherRSA.doFinal(symmetricKey);
        FileOutputStream writeRSA = new FileOutputStream("kxy.rsacipher");
        writeRSA.write(encryptedKxy);
        writeRSA.close();
        keyReader.close();


    }




}