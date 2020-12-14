// Student name:    Muhammad Umar
// Student No.      17313893

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.nio.file.*;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;


public class Assignment1{

    public static void main(String[] args){

        BigInteger prime_modules_p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        // System.out.println(prime_modules_p.bitLength());

        BigInteger generator_g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);
        // System.out.println(generator_g.bitLength());

        BigInteger public_shared_A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);
        // System.out.println(public_shared_A.bitLength());

        BigInteger secret_value_b = new BigInteger("46a40f966030d0fdb453ab9a2e95ffeac2ebeea2ed9ace8b36890133b771e037e5c8284d00262dde2b341df72d972f7fac4ef323ae3201555b68a6aa9acd58a01ed658e646fa841d980a6d76ec5a651250027518e0257522bca9329ddd2fe14fedc0c6bc0d3b1d54bd24f6c91e3bcb2328ae091d4dd5f48f21e155dbda0277ab", 16);
        // System.out.println(secret_value_b.toString(16) + "\n");
        // System.out.println(secret_value_b.bitLength());

        BigInteger public_shared_B = modPow(generator_g, secret_value_b, prime_modules_p);
        // System.out.println(public_shared_B.toString(16) + "\n");
        // System.out.println(public_shared_B.bitLength());

        BigInteger shared_secret_s = modPow(public_shared_A, secret_value_b, prime_modules_p);
        // System.out.println("'shared_secret_s' in hex: " + shared_secret_s.toString(16) + "\n");
        // System.out.println("length of 'shared_secret_s' before sha256: " + shared_secret_s.bitLength() + "\n");


        byte[] aes_key_k = sha256(shared_secret_s);     // getting the sha256 hash of 'shared_secret_s'      
        // System.out.println("'shared_secret_s' in hex after sha256: " + bytesToHex(aes_key_k) + "\n");
        // System.out.println("length of 'shared_secret_s' after sha256: " + bytesToHex(aes_key_k).length() + "\n");


        // Steps for encryption
        byte[] iv = generateRandomValue(16);        // getting a 128 bit IV
        writeToTextFile("IV.txt", bytesToHex(iv));          // storing the IV to the IV.txt
        // System.out.println(iv);

        writeToTextFile("DH.txt", public_shared_B.toString(16));        // public value B stored as asked

        byte[] file = readTextFile(args[0]);        // reading the file to be encrypted as bytes
        byte[] aesEncrypt = encryptFile(file, aes_key_k, iv);       // encrypting the file
        System.out.println(bytesToHex(aesEncrypt));
        // writeToTextFile("Encryption.txt", bytesToHex(aesEncrypt));
        
        // Steps for decryption (not finished)
        // byte[] encryptedFileBytes = readTextFile("Encryption.txt");
        // System.out.println(encryptedFileBytes);
        // byte[] aesEncrypt = encryptFile(file, aes_key_k, iv);
        // writeToTextFile("Encryption.txt", bytesToHex(aesEncrypt));


    }


    // Modular exponentiation implementaiton according to what I have learned from the lecture notes
    // Dosne't work with negative exponents
    public static BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod)
    {
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);
        for (int idx = 0; idx < exp.bitLength(); ++idx) {
            if (exp.testBit(idx)) {
                result = result.multiply(base).mod(mod);
            }
            base = base.multiply(base).mod(mod);
            }
        return result;
    }
    

    // SHA 256 implementation
    public static byte[] sha256(BigInteger text) {
        try {
            MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
            // System.out.println(bytesToHex(text.toByteArray()));
            byte[] result = msgDigest.digest(text.toByteArray());
            return result;
        } 
        
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    // Turns a given byte array into a hexadecimal string
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    public static String bytesToHex(byte[] data) {
        char[] c = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            c[i * 2] = HEX_CHARS[(data[i] >> 4) & 0xf];
            c[i * 2 + 1] = HEX_CHARS[data[i] & 0xf];
        }
        return new String(c);
    }

    // reading file into the system as byte array
    public static byte[] readTextFile(String fileName){
        try{
            return Files.readAllBytes(Paths.get(fileName));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // writing the content to fileName 
    public static void writeToTextFile(String fileName, String content){
        try{
            Files.write(Paths.get(fileName), content.getBytes(), StandardOpenOption.CREATE);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    // use secure random class to generate random 'numBytes' bit key
    public static byte[] generateRandomValue( int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // Padding the file a block size of 128-bits(16 bytes)
    public static byte[] paddingFile(byte[] bFile) {
        int eBytes = bFile.length % 16 == 0 ? 16 : 16 - bFile.length % 16;
        byte[] pBytes = Arrays.copyOf(bFile, bFile.length + eBytes);
        pBytes[bFile.length] = (byte) Integer.parseInt("10000000", 2);
        return pBytes;
    }
    
    // Encrypts the padded file using aes_key and iv
    public static byte[] encryptFile(byte[] file, byte[] key, byte[] iVector) {
        try
        {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iVector);

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            byte[] paddedFile = paddingFile(file);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(paddedFile);
            return encrypted;

        } 
        catch (Exception e) 
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    // public static byte[] decryptFile(byte[] file, byte[] key, byte[] iVector) {
    //     try
    //     {
            

    //     } 
    //     catch (Exception e) 
    //     {
    //         System.out.println("Error while encrypting: " + e.toString());
    //     }
    //     return null;
    // }


}