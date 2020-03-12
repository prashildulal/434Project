import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
 
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
 
// Java 8 example for RSA-AES encryption/decryption.
// Uses strong encryption with 2048 key size.
public class RSAEncryptionJava8 {
 
    public static void main(String[] args) throws Exception {
        String plainText = "Hello World!";
 
        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys();
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey publicKey = (PublicKey) keys.get("public");
 
        // First create an AES Key
        String secretAESKeyString = getSecretAESKeyAsString();
 
        // Encrypt our data with AES key
        String encryptedText = encryptTextUsingAES(plainText, secretAESKeyString);
 
        // Encrypt AES Key with RSA Private Key
        String encryptedAESKeyString = encryptAESKey(secretAESKeyString, privateKey);
 
        // The following logic is on the other side.
 
        // First decrypt the AES Key with RSA Public key
        String decryptedAESKeyString = decryptAESKey(encryptedAESKeyString, publicKey);
 
        // Now decrypt data using the decrypted AES key!
        String decryptedText = decryptTextUsingAES(encryptedText, decryptedAESKeyString);
 
        System.out.println("input:" + plainText);
        System.out.println("AES Key:" + secretAESKeyString);
        System.out.println("Public Key:" + publicKey);
        System.out.println("Private Key:" + privateKey);
        System.out.println("decrypted:" + decryptedText);
        System.out.println("Encrypted Text: " + encryptedText);
    }
 
    // Create a new AES key. Uses 128 bit (weak)
    public static String getSecretAESKeyAsString() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        String encodedKey = Base64.getEncoder().encodeToString(secKey.getEncoded());
        return encodedKey;
    }
 
    // Encrypt text using AES key
    public static String encryptTextUsingAES(String plainText, String aesKeyString) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
 
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(byteCipherText);
    }
 
    // Decrypt text using AES key
    public static String decryptTextUsingAES(String encryptedText, String aesKeyString) throws Exception {
 
        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
 
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
        byte[] bytePlainText = aesCipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(bytePlainText);
    }
 
    // Get RSA keys. Uses key size of 2048.
    private static Map<String, Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
 
        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }
 
    // Decrypt AES Key using RSA public key
    private static String decryptAESKey(String encryptedAESKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedAESKey)));
    }
 
    // Encrypt AES Key using RSA private key
    private static String encryptAESKey(String plainAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainAESKey.getBytes()));
    }
 
}