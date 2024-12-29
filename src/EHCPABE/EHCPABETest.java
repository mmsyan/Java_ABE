package EHCPABE;

import java.util.HashMap;

public class EHCPABETest {

    public static void testCase1() throws Exception {
        //测试文件路径
        String skFilePath = "src/EHCPABE/EHCPABEFile/test1/sk.properties";
        String ctFilePath = "src/EHCPABE/EHCPABEFile/test1/ct.properties";
        System.out.println("\n测试案例1：");
        // 初始化操作，设置属性上限为10

        HashMap<String, String> m1 = new HashMap<>();
        m1.put("src/EHCPABE/EHCPABEFile/test1/FileA.txt", "src/EHCPABE/EHCPABEFile/test1/CiphertextA.txt");
        m1.put("src/EHCPABE/EHCPABEFile/test1/FileB.txt", "src/EHCPABE/EHCPABEFile/test1/CiphertextB.txt");
        m1.put("src/EHCPABE/EHCPABEFile/test1/FileC.txt", "src/EHCPABE/EHCPABEFile/test1/CiphertextC.txt");
        m1.put("src/EHCPABE/EHCPABEFile/test1/FileD.txt", "src/EHCPABE/EHCPABEFile/test1/CiphertextD.txt");

        HashMap<String, String> m2 = new HashMap<>();
        m2.put("src/EHCPABE/EHCPABEFile/test1/FileA.txt", "src/EHCPABE/EHCPABEFile/test1/decryptedTextA.txt");
        m2.put("src/EHCPABE/EHCPABEFile/test1/FileB.txt", "src/EHCPABE/EHCPABEFile/test1/decryptedTextB.txt");
        m2.put("src/EHCPABE/EHCPABEFile/test1/FileC.txt", "src/EHCPABE/EHCPABEFile/test1/decryptedTextC.txt");
        m2.put("src/EHCPABE/EHCPABEFile/test1/FileD.txt", "src/EHCPABE/EHCPABEFile/test1/decryptedTextD.txt");

        EHCPABE ehcpabeInstance = new EHCPABE(10, m1, m2);
        ehcpabeInstance.setUp("a.properties");

        // 用户输入自己属性对应的访问控制树来生成密钥
        int[] userAttributes = new int[]{1, 2, 5, 6};
        ehcpabeInstance.keyGeneration(userAttributes, skFilePath);


        AccessTreeEHCPABE tree1 = AccessTreeEHCPABE.getInstance1();
        ehcpabeInstance.encrypt(tree1, ctFilePath);


        ehcpabeInstance.decrypt(tree1, userAttributes, skFilePath, ctFilePath);
    }

    public static void main(String[] args) throws Exception {
        testCase1();
    }
}
