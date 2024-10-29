package Utils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * AESUtils - AES加密与解密工具类
 *
 * 该类提供了用于加密和解密字符串和文件的实用方法。
 * 使用256位AES密钥和"SHA-256"哈希算法生成安全的密钥。
 */
public class AESUtils {

    private static final int KEY_SIZE = 256;  // AES密钥长度，设置为256位
    private static final String ALGORITHM = "AES";  // 加密算法名称

    /**
     * 使用随机生成器创建AES密钥
     *
     * @return 生成的SecretKey对象
     * @throws Exception 如果出现异常
     */
    public static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);  // 获取AES的Key生成器
        keyGen.init(KEY_SIZE);  // 初始化生成器的密钥长度为256位
        return keyGen.generateKey();  // 生成并返回随机AES密钥
    }

    /**
     * 根据输入的字节数组生成AES密钥（确保输入一致性，增强安全性）
     *
     * @param bytes 密钥的输入字节数组
     * @return SecretKey - 生成的AES密钥
     * @throws Exception 如果出现异常
     */
    public static SecretKey generateSecretKey(byte[] bytes) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");  // 创建SHA-256消息摘要实例
        byte[] hashedBytes = sha.digest(bytes);  // 对输入字节进行哈希处理，生成256位的哈希值

        // 提取前32字节（256位）作为AES密钥
        byte[] keyBytes = new byte[KEY_SIZE / 8];
        System.arraycopy(hashedBytes, 0, keyBytes, 0, keyBytes.length);

        return new SecretKeySpec(keyBytes, ALGORITHM);  // 创建AES密钥并返回
    }

    /**
     * 将AES密钥转换为字符串（Base64编码形式）
     *
     * @param secretKey AES密钥对象
     * @return 编码后的密钥字符串
     */
    public static String keyToString(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());  // 使用Base64编码并返回字符串
    }

    /**
     * 从Base64编码的字符串生成AES密钥对象
     *
     * @param keyStr Base64编码的密钥字符串
     * @return SecretKey - 生成的AES密钥对象
     */
    public static SecretKey stringToKey(String keyStr) {
        byte[] decodedKey = Base64.getDecoder().decode(keyStr);  // 将Base64解码为字节数组
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);  // 创建AES密钥对象并返回
    }

    /**
     * 加密字符串数据
     *
     * @param data 要加密的明文字符串
     * @param secretKey AES密钥
     * @return 加密后的Base64编码字符串
     * @throws Exception 如果出现异常
     */
    public static String encrypt(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);  // 创建AES Cipher实例
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);  // 初始化为加密模式
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));  // 加密字符串并返回字节数组
        return Base64.getEncoder().encodeToString(encryptedBytes);  // 使用Base64编码加密字节并返回
    }

    /**
     * 解密字符串数据
     *
     * @param encryptedData Base64编码的加密字符串
     * @param secretKey AES密钥
     * @return 解密后的明文字符串
     * @throws Exception 如果出现异常
     */
    public static String decrypt(String encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);  // 创建AES Cipher实例
        cipher.init(Cipher.DECRYPT_MODE, secretKey);  // 初始化为解密模式
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);  // 解码Base64加密数据
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);  // 解密数据并返回字节数组
        return new String(decryptedBytes, "UTF-8");  // 将解密的字节转换为字符串并返回
    }

    /**
     * 使用AES加密文件
     *
     * @param inputFile 待加密的文件
     * @param outputFile 加密后的输出文件
     * @param secretKey AES密钥
     * @throws Exception 如果出现异常
     */
    public static void encrypt(File inputFile, File outputFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);  // 创建AES Cipher实例
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);  // 初始化为加密模式

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile);
             CipherOutputStream cipherOut = new CipherOutputStream(outputStream, cipher)) {

            byte[] buffer = new byte[4096];  // 缓冲区大小
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {  // 按缓冲区大小读取文件
                cipherOut.write(buffer, 0, bytesRead);  // 写入加密后的数据
            }
        }
    }

    /**
     * 使用AES解密文件
     *
     * @param encryptedFile 加密的文件
     * @param outputFile 解密后的输出文件
     * @param secretKey AES密钥
     * @throws Exception 如果出现异常
     */
    public static void decrypt(File encryptedFile, File outputFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);  // 创建AES Cipher实例
        cipher.init(Cipher.DECRYPT_MODE, secretKey);  // 初始化为解密模式

        try (FileInputStream inputStream = new FileInputStream(encryptedFile);
             CipherInputStream cipherIn = new CipherInputStream(inputStream, cipher);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[4096];  // 缓冲区大小
            int bytesRead;
            while ((bytesRead = cipherIn.read(buffer)) != -1) {  // 按缓冲区大小读取加密文件
                outputStream.write(buffer, 0, bytesRead);  // 写入解密后的数据
            }
        }
    }

    /**
     * 测试方法：用于演示文件的AES加密和解密
     */
    public static void main(String[] args) {
        try {
            SecretKey secretKey = generateSecretKey("MySecretKey12345".getBytes("UTF-8"));  // 从字符串生成密钥

            // 指定输入、加密和解密文件路径
            File inputFile = new File("src/Utils/AESFile/input.txt");
            File encryptedFile = new File("src/Utils/AESFile/encrypted.txt");
            File decryptedFile = new File("src/Utils/AESFile/decrypted.txt");

            encrypt(inputFile, encryptedFile, secretKey);  // 加密文件
            System.out.println("File encrypted successfully.");

            decrypt(encryptedFile, decryptedFile, secretKey);  // 解密文件
            System.out.println("File decrypted successfully.");

        } catch (Exception e) {
            e.printStackTrace();  // 捕获异常并打印堆栈信息
        }
    }
}
