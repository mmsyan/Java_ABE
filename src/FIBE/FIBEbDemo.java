package FIBE;

import it.unisa.dia.gas.jpbc.Element;

/**
 * FIBE Demo - 基于属性的加密（FIBE）方案演示类
 * 本类展示了如何使用FIBE加密方案进行加密、解密操作，并提供了多个测试案例，展示不同的属性宇宙大小、容错距离等参数的使用。
 *
 * 作者: mmsyan
 * 完成时间: 2024-12-18
 * 参考文献: Fuzzy Identity-Based Encryption
 */
public class FIBEbDemo {

    /**
     * 测试案例1：测试基本的FIBE加密解密功能
     * 使用属性宇宙为【0, 1, 2, 3, 4, 5, 6, 7, 8, 9】以及容错距离为3的参数，演示生成密钥、加密和解密过程。
     * 输入的用户属性为【1, 2, 3, 4】，密文属性为【2, 3, 4, 5】。
     */
    public static void testCase1() {
        String skFilePath = "src/FIBE/FIBEbFile/test1/sk.properties";
        String ctFilePath = "src/FIBE/FIBEbFile/test1/ct.properties";

        System.out.println("\n测试案例1：");
        // 属性集合长度不超过10即可，可以超出【0, 1, 2, 3, 4, 5, 6, 7, 8, 9】的范围达到大宇宙。 容错距离：3
        FIBEb fibeInstance = new FIBEb(10, 3);
        fibeInstance.setUp("a.properties");
        int[] userAttributes = new int[]{100, 200, 300, 400};
        fibeInstance.keyGeneration(userAttributes, skFilePath); // 为属性为【100, 200, 300, 400】的用户生成密钥
        Element M = fibeInstance.generateRandomPlainText(); // 生成随机明文
        System.out.println("测试案例1中M 是 " + M); // 打印随机明文
        fibeInstance.encrypt(new int[]{200, 300, 400, 500}, M, ctFilePath); // 设置密文属性为【200, 300, 400, 500】
        Element M_ = fibeInstance.decrypt(userAttributes, skFilePath, ctFilePath);
        System.out.println("测试案例1中M_ 是 " + M_); // 可以成功解密
    }

    /**
     * 测试案例2：测试属性宇宙较小的情况
     * 使用属性宇宙为【0, 2, 4】以及容错距离为2的参数，演示加密和解密过程。
     * 输入的用户属性为【0, 2, 4】，密文属性为【1, 2, 3】。
     */
    public static void testCase2() {
        String skFilePath = "src/FIBE/FIBEFile/test2/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/test2/ct.properties";

        System.out.println("\n测试案例2：");
        FIBEa fibeInstance = new FIBEa(5, 2);
        fibeInstance.setUp("a.properties");

        try {
            fibeInstance.keyGeneration(new int[]{0, 2, 4}, skFilePath); // 为属性【0, 2, 4】的用户生成密钥
            fibeInstance.encrypt(new int[]{}, fibeInstance.generateRandomPlainText(), ctFilePath); // 空属性
        } catch (Exception e) {
            System.out.println("测试案例2发生错误: " + e.getMessage());
        }
    }


    /**
     * 主方法，用于演示FIBE Section6 Large Universe Construction加密方案
     * @param args 命令行参数
     * @throws Exception 如果在加密或解密过程中发生错误
     */
    public static void main(String[] args) throws Exception {
        testCase1();

    }
}
