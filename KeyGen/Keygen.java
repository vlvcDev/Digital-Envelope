// Students: Vincent Cordova, Jessica Nguyen

import java.io.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import java.security.spec.RSAPrivateKeySpec;
import java.math.BigInteger;

public class Keygen {

    public static void main(String[] args) throws Exception {

        // 1. Create a pair of RSA public and private keys for X, Kx+ and Kx-
        SecureRandom randomX = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, randomX);
        // RSA Plaintext block must be <= 117 bytes
        // RSA Ciphertext block must always be 128 bytes
        KeyPair keyPairX = keyPairGenerator.generateKeyPair();
        Key kxPublic = keyPairX.getPublic();
        Key kxPrivate = keyPairX.getPrivate();

        // 2. Create a pair of RSA public and private keys for Y, Ky+ and Ky– ;
        KeyPair keyPairY = keyPairGenerator.generateKeyPair();
        Key kyPublic = keyPairY.getPublic();
        Key kyPrivate = keyPairY.getPrivate();

        // 3. Get the modulus and exponent of each RSA public or private key and save them into files named “XPublic.key”, “XPrivate.key”,
        // “YPublic.key”, and “YPrivate.key”, respectively;
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec kxPublicKeySpec = factory.getKeySpec(kxPublic, RSAPublicKeySpec.class);
        RSAPrivateKeySpec kxPrivateKeySpec = factory.getKeySpec(kxPrivate, RSAPrivateKeySpec.class);
        
        RSAPublicKeySpec kyPublicKeySpec = factory.getKeySpec(kyPublic, RSAPublicKeySpec.class);
        RSAPrivateKeySpec kyPrivateKeySpec = factory.getKeySpec(kyPrivate, RSAPrivateKeySpec.class);

        writeToFile("XPublic.key", kxPublicKeySpec.getModulus(), kxPublicKeySpec.getPublicExponent());
        writeToFile("XPrivate.key", kxPrivateKeySpec.getModulus(), kxPrivateKeySpec.getPrivateExponent());
        writeToFile("YPublic.key", kyPublicKeySpec.getModulus(), kyPublicKeySpec.getPublicExponent());
        writeToFile("YPrivate.key", kyPrivateKeySpec.getModulus(), kyPrivateKeySpec.getPrivateExponent());

        // 4. Take a 16-character user input from the keyboard and save this 16-character string to a file named “symmetric.key”. This
        // string’s 128-bit UTF-8 encoding will be used as the 128-bit AES symmetric key, Kxy, in your application
        Scanner s = new Scanner(System.in);
        System.out.println("Input your 16-character String for the symmetric key: ");
        String rawInput = s.nextLine();
        System.out.println("Symmetric Key: " + rawInput);
        s.close();
        FileWriter w = new FileWriter("symmetric.key");
        w.write(rawInput);
        w.close();
    }

    public static void writeToFile(String fileName, BigInteger modulus, BigInteger exponent) throws IOException {
        System.out.println("Writing to: " + fileName + ",\n Modulus = " + modulus.toString() + ",\n Exponent = " + exponent.toString());

        ObjectOutputStream oOut = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));

        try {
            oOut.writeObject(modulus);
            oOut.writeObject(exponent);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oOut.close();
        }
    }
}
