package KPABE;

import it.unisa.dia.gas.jpbc.Element;

public class KPABEbTest {

    public static void testCase1() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEbFile/test1/sk.properties";
        String ctFilePath = "src/KPABE/KPABEbFile/test1/ct.properties";
        System.out.println("\n测试案例1：");

        // 初始化操作，设置属性宇宙为【1, 2, 3, 4, 5, 6, 7, 8, 9, 10】
        KPABEb kpabeInstance = new KPABEb(10);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1, 2, 5}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE tree1 = AccessTreeKPABE.getInstance1();
        kpabeInstance.keyGeneration(tree1, skFilePath);

        Element M_ = kpabeInstance.decrypt(tree1, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase2() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEbFile/test2/sk.properties";
        String ctFilePath = "src/KPABE/KPABEbFile/test2/ct.properties";
        System.out.println("\n测试案例2：");

        // 初始化操作，设置属性宇宙为【1, 2, 3, 4, 5, 6, 7, 8, 9, 10】
        KPABEb kpabeInstance = new KPABEb(10);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1, 2, 3, 4, 5}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE tree1 = AccessTreeKPABE.getInstance1();
        kpabeInstance.keyGeneration(tree1, skFilePath);

        Element M_ = kpabeInstance.decrypt(tree1, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase3() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEaFile/test3/sk.properties";
        String ctFilePath = "src/KPABE/KPABEaFile/test3/ct.properties";
        System.out.println("\n测试案例3：");

        // 初始化操作，设置属性宇宙为【1, 2, 3, 4, 5, 6, 7, 8, 9, 10】
        KPABEa kpabeInstance = new KPABEa(10);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1, 2, 3, 4}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE tree1 = AccessTreeKPABE.getInstance1();
        kpabeInstance.keyGeneration(tree1, skFilePath);

        Element M_ = kpabeInstance.decrypt(tree1, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase4() { // 无法通过
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEaFile/test4/sk.properties";
        String ctFilePath = "src/KPABE/KPABEaFile/test4/ct.properties";
        System.out.println("\n测试案例4：");

        // 初始化操作，设置属性宇宙为【1, 2, 3, 4, 5, 6, 7, 8, 9, 10】
        KPABEa kpabeInstance = new KPABEa(10);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{2, 3, 4}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE tree1 = AccessTreeKPABE.getInstance1();
        kpabeInstance.keyGeneration(tree1, skFilePath);

        Element M_ = kpabeInstance.decrypt(tree1, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase5() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEaFile/test5/sk.properties";
        String ctFilePath = "src/KPABE/KPABEaFile/test5/ct.properties";
        System.out.println("\n测试案例5：");
        // 初始化操作，设置属性上限为10
        KPABEa kpabeInstance = new KPABEa(20);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1, 3, 6}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE tree2 = AccessTreeKPABE.getInstance2();
        kpabeInstance.keyGeneration(tree2, skFilePath);

        Element M_ = kpabeInstance.decrypt(tree2, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase6() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEaFile/test6/sk.properties";
        String ctFilePath = "src/KPABE/KPABEaFile/test6/ct.properties";
        System.out.println("\n测试案例6：");
        // 初始化操作，设置属性上限为10
        KPABEa kpabeInstance = new KPABEa(20);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1,2, 3,4,5, 6,7,8,9,10,11,12}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE tree2 = AccessTreeKPABE.getInstance2();
        kpabeInstance.keyGeneration(tree2, skFilePath);

        Element M_ = kpabeInstance.decrypt(tree2, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase7() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEaFile/test7/sk.properties";
        String ctFilePath = "src/KPABE/KPABEaFile/test7/ct.properties";
        System.out.println("\n测试案例7：");
        // 初始化操作，设置属性上限为10
        KPABEa kpabeInstance = new KPABEa(20);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1, 3, 6}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE userAttributes = AccessTreeKPABE.getInstance3();
        kpabeInstance.keyGeneration(userAttributes, skFilePath);

        Element M_ = kpabeInstance.decrypt(userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase8() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEaFile/test8/sk.properties";
        String ctFilePath = "src/KPABE/KPABEaFile/test8/ct.properties";
        System.out.println("\n测试案例8：");
        // 初始化操作，设置属性上限为10
        KPABEa kpabeInstance = new KPABEa(20);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE userAttributes = AccessTreeKPABE.getInstance4();
        kpabeInstance.keyGeneration(userAttributes, skFilePath);

        Element M_ = kpabeInstance.decrypt(userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase9() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEaFile/test9/sk.properties";
        String ctFilePath = "src/KPABE/KPABEaFile/test9/ct.properties";
        System.out.println("\n测试案例9：");
        // 初始化操作，设置属性上限为10
        KPABEa kpabeInstance = new KPABEa(20);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{2,3,4,5, 6,7,8,9,10,11,12}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE userAttributes = AccessTreeKPABE.getInstance4();
        kpabeInstance.keyGeneration(userAttributes, skFilePath);

        Element M_ = kpabeInstance.decrypt(userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase10() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEbFile/test10/sk.properties";
        String ctFilePath = "src/KPABE/KPABEbFile/test10/ct.properties";
        System.out.println("\n测试案例10：");

        // 初始化操作，设置属性集合最大值为10
        KPABEb kpabeInstance = new KPABEb(10);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1, 2}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        AccessTreeKPABE tree1 = AccessTreeKPABE.getInstance5();
        kpabeInstance.keyGeneration(tree1, skFilePath);

        Element M_ = kpabeInstance.decrypt(tree1, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }



    public static void main(String[] args) {
        testCase10();


    }
}
