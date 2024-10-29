package Utils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.util.Base64;

public class AESUtils {

    private static final int KEY_SIZE = 256;  // AES密钥长度，256位
    private static final String ALGORITHM = "AES";

    // 使用随机生成器生成AES密钥
    public static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE);
        return keyGen.generateKey();
    }

    // 根据输入的字节数组生成AES密钥，增加安全性处理
    public static SecretKey generateSecretKey(byte[] bytes) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = sha.digest(bytes);

        byte[] keyBytes = new byte[KEY_SIZE / 8];
        System.arraycopy(hashedBytes, 0, keyBytes, 0, keyBytes.length);

        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    // 将密钥转换为字符串格式
    public static String keyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    // 将字符串转换回SecretKey
    public static SecretKey stringToKey(String keyStr) {
        byte[] decodedKey = Base64.getDecoder().decode(keyStr);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);
    }

    // 字符串加密
    public static String encrypt(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 字符串解密
    public static String decrypt(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, "UTF-8");
    }

    // 文件加密
    public static void encrypt(File inputFile, File outputFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile);
             CipherOutputStream cipherOut = new CipherOutputStream(outputStream, cipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOut.write(buffer, 0, bytesRead);
            }
        }
    }

    // 文件解密
    public static void decrypt(File encryptedFile, File outputFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(encryptedFile);
             CipherInputStream cipherIn = new CipherInputStream(inputStream, cipher);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cipherIn.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    // 测试AES加解密
    public static void main(String[] args) {
        try {
            SecretKey secretKey = generateSecretKey("MySecretKey12345".getBytes("UTF-8"));

            // 测试文件加密解密
            File inputFile = new File("src/Utils/AESFile/input.txt");
            File encryptedFile = new File("src/Utils/AESFile/encrypted.aes");
            File decryptedFile = new File("src/Utils/AESFile/decrypted.txt");

            encrypt(inputFile, encryptedFile, secretKey);
            System.out.println("File encrypted successfully.");

            decrypt(encryptedFile, decryptedFile, secretKey);
            System.out.println("File decrypted successfully.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
