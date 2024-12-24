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
public class FIBEaDemo {

    /**
     * 测试案例1：测试基本的FIBE加密解密功能
     * 使用属性宇宙为【0, 1, 2, 3, 4, 5, 6, 7, 8, 9】以及容错距离为3的参数，演示生成密钥、加密和解密过程。
     * 输入的用户属性为【1, 2, 3, 4】，密文属性为【2, 3, 4, 5】。
     */
    public static void testCase1() {
        String skFilePath = "src/FIBE/FIBEFile/test1/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/test1/ct.properties";

        System.out.println("\n测试案例1：");
        FIBEa fibeInstance = new FIBEa(10, 3); // 属性【0, 1, 2, 3, 4, 5, 6, 7, 8, 9】 容错距离：3
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{1, 2, 3, 4}, skFilePath); // 为属性为【1, 2, 3, 4】的用户生成密钥
        Element M = fibeInstance.generateRandomPlainText(); // 生成随机明文
        System.out.println("测试案例1中M 是 " + M); // 打印随机明文
        fibeInstance.encrypt(new int[]{2, 3, 4, 5}, M, ctFilePath); // 设置密文属性为【2, 3, 4, 5】
        Element M_ = fibeInstance.decrypt(new int[]{1, 2, 3, 4}, skFilePath, ctFilePath);
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
     * 测试案例3：测试更大的属性宇宙和不同的参数距离
     * 使用属性宇宙为【0, 1, 2, ..., 19】以及容错距离为5的参数，演示加密和解密过程。
     * 输入的用户属性为【0, 5, 6, 10, 11, 15】, 密文属性为【0, 5, 6, 8, 11, 15, 16】。
     */
    public static void testCase3() {
        String skFilePath = "src/FIBE/FIBEFile/test3/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/test3/ct.properties";

        System.out.println("\n测试案例3：");
        FIBEa fibeInstance = new FIBEa(20, 5);
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{1, 5, 6, 10, 11, 15}, skFilePath); // 为属性【1, 5, 6, 10, 11, 15】的用户生成密钥
        Element M = fibeInstance.generateRandomPlainText(); // 生成随机明文
        System.out.println("测试案例3中M 是 " + M);
        fibeInstance.encrypt(new int[]{1, 5, 6, 8, 11, 15, 16}, M, ctFilePath); // 设置密文属性为【1, 5, 6, 8, 11, 15, 16】
        Element M_ = fibeInstance.decrypt(new int[]{1, 5, 6, 10, 11, 15}, skFilePath, ctFilePath);
        System.out.println("测试案例3中M_ 是 " + M_);
    }

    /**
     * 测试案例4：测试属性宇宙大小为奇数的情况
     * 使用属性宇宙为【0, 1, ..., 10】以及容错距离为3的参数，演示加密和解密过程。
     * 输入的用户属性为【1, 3, 6, 9】, 密文属性为【2, 4, 7, 10】。
     */
    public static void testCase4() {
        String skFilePath = "src/FIBE/FIBEFile/test4/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/test4/ct.properties";

        System.out.println("\n测试案例4：");
        FIBEa fibeInstance = new FIBEa(11, 3);
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{1, 3, 6, 9}, skFilePath); // 为属性【1, 3, 6, 9】的用户生成密钥
        Element M = fibeInstance.generateRandomPlainText(); // 生成随机明文
        System.out.println("测试案例4中M 是 " + M);
        fibeInstance.encrypt(new int[]{2, 4, 7, 10}, M, ctFilePath); // 设置密文属性为【2, 4, 7, 10】
        Element M_ = fibeInstance.decrypt(new int[]{1, 3, 6, 9}, skFilePath, ctFilePath);
        System.out.println("测试案例4中M_ 是 " + M_);
    }

    /**
     * 测试案例5：测试属性宇宙大小为1的情况
     * 这是一个特殊情况，属性宇宙只有一个属性【0】，容错距离为1，测试加密和解密过程。
     * 输入的用户属性为【0】, 密文属性为【0】。
     */
    public static void testCase5() {
        String skFilePath = "src/FIBE/FIBEFile/test5/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/test5/ct.properties";

        System.out.println("\n测试案例5：");
        FIBEa fibeInstance = new FIBEa(1, 1);
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{1}, skFilePath); // 为属性【1】的用户生成密钥
        Element M = fibeInstance.generateRandomPlainText(); // 生成随机明文
        System.out.println("测试案例5中M 是 " + M);
        fibeInstance.encrypt(new int[]{1}, M, ctFilePath); // 设置密文属性为【1】
        Element M_ = fibeInstance.decrypt(new int[]{1}, skFilePath, ctFilePath);
        System.out.println("测试案例5中M_ 是 " + M_);
    }

    /**
     * 测试案例6：测试容错距离为最大值的情况
     * 测试容错距离设为属性宇宙大小减1的极限值情况，演示加密和解密过程。
     * 属性宇宙为【0, 1, ..., 10】, 容错距离为10，输入的用户属性为【0, 1, 2, ..., 9】。
     */
    public static void testCase6() {
        String skFilePath = "src/FIBE/FIBEFile/test6/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/test6/ct.properties";

        System.out.println("\n测试案例6：");
        FIBEa fibeInstance = new FIBEa(11, 10);
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, skFilePath); // 为属性【0, 1, ..., 9】的用户生成密钥
        Element M = fibeInstance.generateRandomPlainText(); // 生成随机明文
        System.out.println("测试案例6中M 是 " + M);
        fibeInstance.encrypt(new int[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, M, ctFilePath); // 设置密文属性为【0, 1, 2, ..., 10】
        Element M_ = fibeInstance.decrypt(new int[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, skFilePath, ctFilePath);
        System.out.println("测试案例6中M_ 是 " + M_);
    }

    /**
     * 测试案例7：测试属性宇宙为完全不相交的用户
     * 测试不同用户的属性宇宙没有交集的情况，验证密钥和密文的有效性。
     */
    public static void testCase7() {
        String skFilePath = "src/FIBE/FIBEFile/test7/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/test7/ct.properties";

        System.out.println("\n测试案例7：");
        FIBEa fibeInstance = new FIBEa(10, 3);
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{1, 3, 5}, skFilePath); // 为属性【1, 3, 5】的用户生成密钥
        Element M = fibeInstance.generateRandomPlainText(); // 生成随机明文
        System.out.println("测试案例7中M 是 " + M);
        fibeInstance.encrypt(new int[]{1, 3, 6}, M, ctFilePath); // 设置密文属性为【1, 3, 6】
        Element M_ = fibeInstance.decrypt(new int[]{1, 3, 5}, skFilePath, ctFilePath);
        System.out.println("测试案例7中M_ 是 " + M_);
    }

    /**
     * 测试案例8：测试空的属性宇宙
     * 测试属性宇宙为空的特殊情况，验证算法如何处理这种情况。
     */
    public static void testCase8() {
        String skFilePath = "src/FIBE/FIBEFile/test8/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/test8/ct.properties";

        System.out.println("\n测试案例8：");
        FIBEa fibeInstance = new FIBEa(0, 0); // 属性宇宙大小为0
        fibeInstance.setUp("a.properties");
        // 这里无法生成密钥或进行加密解密，主要是测试是否能正确处理这种极端情况
        try {
            fibeInstance.keyGeneration(new int[]{}, skFilePath); // 空属性
            fibeInstance.encrypt(new int[]{}, fibeInstance.generateRandomPlainText(), ctFilePath); // 空属性
        } catch (Exception e) {
            System.out.println("测试案例8发生错误: " + e.getMessage());
        }
    }

    /**
     * 主方法，用于演示FIBE section4 加密方案 Our Construction
     * @param args 命令行参数
     * @throws Exception 如果在加密或解密过程中发生错误
     */
    public static void main(String[] args) throws Exception {
        testCase1();
        testCase2();
        testCase3();
        testCase4();
        testCase5();
        testCase6();
        testCase7();
        testCase8();
    }
}
