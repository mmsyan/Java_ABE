package CPABE;

import it.unisa.dia.gas.jpbc.Element;

public class CPABETest {

    public static void testCase1() {
        //测试文件路径
        String skFilePath = "src/CPABE/CPABEFile/test1/sk.properties";
        String ctFilePath = "src/CPABE/CPABEFile/test1/ct.properties";
        System.out.println("\n测试案例1：");
        // 初始化操作，设置属性上限为10
        CPABE cpabeInstance = new CPABE(10);
        cpabeInstance.setUp("a.properties");

        // 用户输入自己属性对应的访问控制树来生成密钥
        int[] userAttributes = new int[]{1, 2, 5};
        cpabeInstance.keyGeneration(userAttributes, skFilePath);

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        AccessTreeCPABE tree1 = AccessTreeCPABE.getInstance1();
        cpabeInstance.encrypt(tree1, M, ctFilePath);


        Element M_ = cpabeInstance.decrypt(tree1, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase2() {
        //测试文件路径
        String skFilePath = "src/CPABE/CPABEFile/test2/sk.properties";
        String ctFilePath = "src/CPABE/CPABEFile/test2/ct.properties";
        System.out.println("\n测试案例2：");
        // 初始化操作，设置属性上限为10
        CPABE cpabeInstance = new CPABE(20);
        cpabeInstance.setUp("a.properties");

        // 用户输入自己属性对应的访问控制树来生成密钥
        int[] userAttributes = new int[]{1, 3, 6};
        cpabeInstance.keyGeneration(userAttributes, skFilePath);

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        AccessTreeCPABE messageAttributes = AccessTreeCPABE.getInstance2();
        cpabeInstance.encrypt(messageAttributes, M, ctFilePath);


        Element M_ = cpabeInstance.decrypt(messageAttributes, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase3() {
        //测试文件路径
        String skFilePath = "src/CPABE/CPABEFile/test3/sk.properties";
        String ctFilePath = "src/CPABE/CPABEFile/test3/ct.properties";
        System.out.println("\n测试案例3：");
        // 初始化操作，设置属性上限为10
        CPABE cpabeInstance = new CPABE(20);
        cpabeInstance.setUp("a.properties");

        // 用户输入自己属性对应的访问控制树来生成密钥
        int[] userAttributes = new int[]{1, 3, 6};
        cpabeInstance.keyGeneration(userAttributes, skFilePath);

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        AccessTreeCPABE messageAttributes = AccessTreeCPABE.getInstance3();
        cpabeInstance.encrypt(messageAttributes, M, ctFilePath);


        Element M_ = cpabeInstance.decrypt(messageAttributes, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase4() {
        //测试文件路径
        String skFilePath = "src/CPABE/CPABEFile/test4/sk.properties";
        String subSetSkFilePath = "src/CPABE/CPABEFile/test4/subSetSk.properties";
        String ctFilePath = "src/CPABE/CPABEFile/test4/ct.properties";

        System.out.println("\n测试案例4：Delegate()函数测试");
        // 初始化操作，设置属性上限为10
        CPABE cpabeInstance = new CPABE(10);
        cpabeInstance.setUp("a.properties");

        // 用户输入自己属性对应的访问控制树来生成密钥
        int[] userAttributes = new int[]{1, 2, 5};
        cpabeInstance.keyGeneration(userAttributes, skFilePath);

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabeInstance.generateRandomPlainText();
        System.out.println("M 是 " + M);
        AccessTreeCPABE tree1 = AccessTreeCPABE.getInstance1();
        cpabeInstance.encrypt(tree1, M, ctFilePath);

        Element M_ = cpabeInstance.decrypt(tree1, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);

        // 子属性集合，测试delegate委派函数
        int[] subSetUserAttributes = new int[]{5, 1};
        cpabeInstance.delegate(userAttributes, subSetUserAttributes, skFilePath, subSetSkFilePath);

        Element M1_ = cpabeInstance.decrypt(tree1, subSetUserAttributes, subSetSkFilePath, ctFilePath);
        System.out.println("M1_ 是 " + M1_);
    }

    public static void main(String[] args) {
        testCase1();
        testCase2();
        testCase3();
        testCase4();
    }
}
