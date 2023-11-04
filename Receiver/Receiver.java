// Students: Vincent Cordova, Jessica Nguyen

import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.KeyFactory;

public class Receiver {
    final private static int BUFFER_SIZE = 32 * 1024;

    final private static String IV = "OOGABOOGAOOGABOO";

    public static void main(String[] args) throws Exception {
        
        // Get ky-
        BigInteger modulus, exponent;
        ObjectInputStream keyReader = new ObjectInputStream(new FileInputStream("YPrivate.key"));
        modulus = (BigInteger)keyReader.readObject();
        exponent = (BigInteger)keyReader.readObject(); 

        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey yPrivateKey = (PrivateKey) keyFactory.generatePrivate(keySpec);


        // Allow user to input name of message file
        Scanner s = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String messageFile = s.nextLine();

        // Read and decrypt C1
        final String C1_PATH = "kxy.rsacipher";
        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.DECRYPT_MODE, yPrivateKey);
        
        BufferedInputStream decryptReader = new BufferedInputStream(new FileInputStream(C1_PATH));
        ByteArrayOutputStream decryptWriter = new ByteArrayOutputStream();
        byte[] decryptedKxyBuffer = new byte[256];
        int bytesRead;

        while ((bytesRead = decryptReader.read(decryptedKxyBuffer)) != -1) {
            decryptWriter.write(decryptedKxyBuffer, 0, bytesRead);
        }

        byte[] encryptedKxy = decryptWriter.toByteArray();

        byte[] decryptedKxy = cipherRSA.doFinal(encryptedKxy);
        
        BufferedOutputStream decryptFileWriter = new BufferedOutputStream(new FileOutputStream("message.kmk", true));
        decryptFileWriter.write(decryptedKxy);
        decryptReader.close();
        decryptWriter.close();
        for (int k=0, j=0; k<decryptedKxy.length; k++, j++) {
            System.out.format("%2X ", decryptedKxy[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
        // RSA ends here

        //AES starts here
        //Get C2 from message.aescipher, each block a multiple of 16
        // last block put into its own byte array
        
        // Initialize cypher with kxy in decrypt mode
        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(decryptedKxy, "AES");
        cipherAES.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
        
        // read message.aeschpher block by block
        BufferedInputStream aesReader = new BufferedInputStream(new FileInputStream("message.aescipher"));
        BufferedOutputStream decryptedMessageWriter = new BufferedOutputStream(new FileOutputStream(messageFile));
        byte[] aesBuffer = new byte[16];
        int currentBytesRead;
        
        while ((currentBytesRead = aesReader.read(aesBuffer)) != -1) {
            byte[] inputChunk = (currentBytesRead < aesBuffer.length) ? Arrays.copyOf(aesBuffer, currentBytesRead) : aesBuffer;

            byte[] decryptChunk = cipherAES.update(inputChunk);

            decryptedMessageWriter.write(decryptChunk);
            decryptFileWriter.write(decryptChunk);
        }

        byte[] endBlock = cipherAES.doFinal();
        if(endBlock.length > 0) {
            decryptedMessageWriter.write(endBlock);
            decryptFileWriter.write(endBlock);
        }

        decryptFileWriter.write(decryptedKxy);

        aesReader.close();
        decryptFileWriter.close();
        decryptedMessageWriter.close();
        keyReader.close();
        


        byte[] newMAC = messageDigestionSHA256("message.kmk");

        byte[] oldMAC = retrieveHashFromKHMACFile("message.khmac");

        boolean matchMAC = true;

        for(int i = 0; i < newMAC.length; i++) {
            if(newMAC[i] != oldMAC[i]) matchMAC = false;
        }

        System.out.println("message.khmac matches message.kmk: " + matchMAC);

        s.close();
    }

    public static byte[] retrieveHashFromKHMACFile(String filename) throws IOException {
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(filename))) {
            byte[] hash = new byte[32];  // SHA-256 produces a 32-byte (256-bit) hash
            int bytesRead = bis.read(hash);
            if (bytesRead != 32) {
                throw new IOException("Unexpected hash length. Expected 32 bytes but read " + bytesRead);
            }

            System.out.println("Hash value: ");
            for (int k=0, j=0; k<hash.length; k++, j++) {
                System.out.format("%2X ", hash[k]) ;
                if (j >= 15) {
                    System.out.println("");
                    j=-1;
            }
        }
            return hash;
        }
    }
    

    // Message digest copied from Sender
    public static byte[] messageDigestionSHA256(String f) throws Exception {
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
        
        return hash;
    }
}
