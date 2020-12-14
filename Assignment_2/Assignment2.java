
// Muhammad Umar
// 17313893

// If you comment out all the 'System.out.println' line you will be able to see the values for each variable.

import java.io.*;
import java.math.*;
import java.util.Random;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.PrivateKey; 
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.KeyFactory;


public class Assignment2 {

    public static void main(String[] args)
    {


        BigInteger encr_exp_e =  new BigInteger("65537");

        BigInteger prime_p = new BigInteger("8aca74e72ff6d9881a1833c1dd14ef0621d037648a7d67314b510a2142c276d1e5618e299b573f6de3b75e79eda983a2666e200d8bcec7296367912805659db3", 16);
        // System.out.println("\nprime_p is => " + prime_p.bitLength() + " bits long");
        // System.out.println("prime_p => " + prime_p.toString(16));
        // System.out.println("Length prime_p => " + prime_p.toString(16).length());
        // System.out.println("prime_p is prime with certainity 1 is => " + prime_p.isProbablePrime(1));
        // System.out.println("---------------------------------------------------------------------------------------------------------------------------------------------------\n");


        BigInteger prime_q = new BigInteger("cadce0006236519af3bbec7e58a5f2da19dd4813b50360243c30a6b5aa95c1700dfdf8111969b83aac236bf1d5c3fc5c8daa1b4c1da953e3c83277a56d9c0b2d", 16);
        // System.out.println("prime_q is => " + prime_q.bitLength() + " bits long");
        // System.out.println("prime_q => " + prime_q.toString(16));
        // System.out.println("Length prime_q => " + prime_q.toString(16).length());
        // System.out.println("prime_q is prime with certainity 1 is => " + prime_q.isProbablePrime(1));
        // System.out.println("---------------------------------------------------------------------------------------------------------------------------------------------------\n");

        // Calculating Modulus n --- Writing it to the file 'Modulus.txt'
        BigInteger product_p_q = prime_p.multiply(prime_q);
        try{
            Files.writeString(Path.of("Modulus.txt"), product_p_q.toString(16));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }

        // System.out.println("product_p_q is => " + product_p_q.bitLength() + " bits long");
        // System.out.println("product_p_q => " + product_p_q.toString(16));
        // System.out.println("Length product_p_q => " + product_p_q.toString(16).length());
        // System.out.println("product_p_q is prime with certainity 1 is => " + product_p_q.isProbablePrime(1));
        // System.out.println("---------------------------------------------------------------------------------------------------------------------------------------------------\n");


        // // Testing Phi function
        // BigInteger a = BigInteger.valueOf(3);
        // BigInteger b = BigInteger.valueOf(5);
        // System.out.println("\nResult should be '8' => AND IT IS !!! => " + phi(a,b).intValue() + "\n");

        // // Calculating phi(n)
        BigInteger phi_of_n = phi(prime_p, prime_q);
        // System.out.println("Phi(n) => "+ phi_of_n.intValue() +"\n");
        

        // // This should be 1 to ensure that 'e' and 'phi(n)' are relatively prime to each other
        // System.out.println("Number should be 1 to ensure that Phi(n) and exponent(e) are relatively prime => And the number is => "+ encr_exp_e.gcd(phi_of_n) +"\n");
        // System.out.println("---------------------------------------------------------------------------------------------------------------------------------------------------\n");
        


        // // My implementaion of the mod inverse
        BigInteger decr_exp_d = multInv(encr_exp_e, phi_of_n);
        // System.out.println("Modular inverse of encr_exp_e(e) " + encr_exp_e.intValue() +" and phi(n) " + phi_of_n.intValue() + " using my implementation " + decr_exp_d.intValue() + "\n");

        // // Using this only for testing purposes, to check if my implementation is correct
        // System.out.println("Modular inverse of encr_exp_e(e) " + encr_exp_e.intValue() +" and phi(n) " + phi_of_n.intValue() + " using java libaray (for testing) " + encr_exp_e.modInverse(phi_of_n).intValue() + "\n");
        // System.out.println("---------------------------------------------------------------------------------------------------------------------------------------------------\n");


        // Reading the file
        byte[] file = readTextFile(args[0]);


        BigInteger fileEncryptedCRT = decryptCRT(file, decr_exp_d, prime_p, prime_q);
        // System.out.println("Decryption (as BigInt) using h(m)^d (mod n) => "+ fileEncryptedCRT +"\n");
        System.out.println(fileEncryptedCRT.toString(16));

       
    }

    // Chinese remainder theorm
    public static BigInteger crt(BigInteger cModPowP, BigInteger inv, BigInteger cModPowQ, BigInteger p, BigInteger q)
    {
        return cModPowP.add(q.multiply((inv.multiply(cModPowP.subtract(cModPowQ))).mod(p)));
    }


    // decrypt function
    public static BigInteger decryptCRT(byte[] file, BigInteger d, BigInteger p, BigInteger q)
    {
        
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");                // init the SHA-256
            byte [] mdHash = md.digest(file);
            BigInteger msgDigest = new BigInteger(bytesToHex(mdHash), 16);

            BigInteger cModPowP = msgDigest.modPow(d.mod(p.subtract(BigInteger.ONE)), p);
            BigInteger cModPowQ = msgDigest.modPow(d.mod(q.subtract(BigInteger.ONE)), q);

            BigInteger iQModP = multInv(q, p);
            BigInteger data = crt(cModPowP, iQModP, cModPowQ, p , q);

            return data;
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }

    }


    // Encrypt Function
	public static BigInteger decrypt(BigInteger message, BigInteger d, BigInteger n)
    {
		return message.modPow(d, n);
	}


    // SHA 256 implementation
    public static byte[] sha256(BigInteger text)
    {
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


    // returns a probable prime of given bitLength 'b'
    public static BigInteger generatePrime(int b)
    {
        BigInteger num = BigInteger.probablePrime(b, new SecureRandom());
        System.out.println("\nA Hex representaion of a " + b + "-bit prime =>\n" + num.toString(16) + "\n");
        System.out.println("Bit-Length of this prime => " + num.bitLength() + "\n");
        return num;
    }


    // reading file into the system as byte array
    public static byte[] readTextFile(String fileName)
    {
        try{
            return Files.readAllBytes(Paths.get(fileName));
        } 
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Calculate the phi
    public static BigInteger phi(BigInteger val1, BigInteger val2)  
    {  
        return val1.subtract(BigInteger.ONE).multiply(val2.subtract(BigInteger.ONE));

    }


    //https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/the-euclidean-algorithm
    // This example was done in python and i changed it to make it work with Big Integer
    public static BigInteger [] extEuclGCD(BigInteger val1, BigInteger val2)
    {
        if(val2 == BigInteger.ZERO)
        {
            return new BigInteger[] {val1, BigInteger.ONE, BigInteger.ZERO};
        }
        else
        {
            BigInteger[] arr = extEuclGCD(val2, val1.mod(val2));
            BigInteger g = arr[0];
            BigInteger x = arr[2];
            BigInteger y = arr[1].subtract((val1.divide(val2)).multiply(arr[2]));
            
            return new BigInteger[] {g, x, y};
        }
            
    }

    // Calculate Multiplicative inverse
    public static BigInteger multInv(BigInteger val1, BigInteger val2)
    {
        BigInteger[] arr = extEuclGCD(val1, val2);
        BigInteger g = arr[0];
        BigInteger a = arr[1];
        if(!g.equals(BigInteger.ONE))
        {
           throw new RuntimeException("Inverse between the two number is not possible");
        }
        else
        {
            return a.mod(val2);
        }
    }

    // Turns a given byte array into a hexadecimal string
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    public static String bytesToHex(byte[] data)
    {
        char[] c = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            c[i * 2] = HEX_CHARS[(data[i] >> 4) & 0xf];
            c[i * 2 + 1] = HEX_CHARS[data[i] & 0xf];
        }
        return new String(c);
    }
        
}