package CPABE_Waters11;

import it.unisa.dia.gas.jpbc.Element;

public class CPABEWaters11Test {

    public static void test1() {
        CPABEWaters11 cpabewaters11Instance = new CPABEWaters11(20);
        cpabewaters11Instance.setUp("a.properties");

        int[] userAttributes = new int[]{1, 2, 3};
        String skFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test1/sk.properties";
        cpabewaters11Instance.keyGeneration(userAttributes, skFilePath);

        CPABELewkoWatersLSSS.Node r = CPABELewkoWatersLSSSTest.getTree1();
        CPABELewkoWatersLSSS messageAccess = new CPABELewkoWatersLSSS(r, cpabewaters11Instance.getBp());
        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabewaters11Instance.getBp().getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        String ctFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test1/ct.properties";
        cpabewaters11Instance.encrypt(messageAccess, M, ctFilePath);

        Element M_  = cpabewaters11Instance.decrypt(messageAccess, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void test2() {
        CPABEWaters11 cpabewaters11Instance = new CPABEWaters11(20);
        cpabewaters11Instance.setUp("a.properties");

        int[] userAttributes = new int[]{1, 2, 3};
        String skFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test2/sk.properties";
        cpabewaters11Instance.keyGeneration(userAttributes, skFilePath);

        CPABELewkoWatersLSSS.Node r = CPABELewkoWatersLSSSTest.getTree2();
        CPABELewkoWatersLSSS messageAccess = new CPABELewkoWatersLSSS(r, cpabewaters11Instance.getBp());
        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabewaters11Instance.getBp().getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        String ctFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test2/ct.properties";
        cpabewaters11Instance.encrypt(messageAccess, M, ctFilePath);

        Element M_  = cpabewaters11Instance.decrypt(messageAccess, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void test3() {
        CPABEWaters11 cpabewaters11Instance = new CPABEWaters11(20);
        cpabewaters11Instance.setUp("a.properties");

        int[] userAttributes = new int[]{1, 2, 5};
        String skFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test3/sk.properties";
        cpabewaters11Instance.keyGeneration(userAttributes, skFilePath);

        CPABELewkoWatersLSSS.Node r = CPABELewkoWatersLSSSTest.getTree2();
        CPABELewkoWatersLSSS messageAccess = new CPABELewkoWatersLSSS(r, cpabewaters11Instance.getBp());
        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabewaters11Instance.getBp().getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        String ctFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test3/ct.properties";
        cpabewaters11Instance.encrypt(messageAccess, M, ctFilePath);

        Element M_  = cpabewaters11Instance.decrypt(messageAccess, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void test4() {
        CPABEWaters11 cpabewaters11Instance = new CPABEWaters11(20);
        cpabewaters11Instance.setUp("a.properties");

        int[] userAttributes = new int[]{1, 2, 3, 5};
        String skFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test4/sk.properties";
        cpabewaters11Instance.keyGeneration(userAttributes, skFilePath);

        CPABELewkoWatersLSSS.Node r = CPABELewkoWatersLSSSTest.getTree2();
        CPABELewkoWatersLSSS messageAccess = new CPABELewkoWatersLSSS(r, cpabewaters11Instance.getBp());
        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabewaters11Instance.getBp().getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        String ctFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test4/ct.properties";
        cpabewaters11Instance.encrypt(messageAccess, M, ctFilePath);

        Element M_  = cpabewaters11Instance.decrypt(messageAccess, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void test5() {
        CPABEWaters11 cpabewaters11Instance = new CPABEWaters11(20);
        cpabewaters11Instance.setUp("a.properties");

        int[] userAttributes = new int[]{1, 2, 4};
        String skFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test5/sk.properties";
        cpabewaters11Instance.keyGeneration(userAttributes, skFilePath);

        CPABELewkoWatersLSSS.Node r = CPABELewkoWatersLSSSTest.getTree1();
        CPABELewkoWatersLSSS messageAccess = new CPABELewkoWatersLSSS(r, cpabewaters11Instance.getBp());
        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabewaters11Instance.getBp().getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        String ctFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test5/ct.properties";
        cpabewaters11Instance.encrypt(messageAccess, M, ctFilePath);

        Element M_  = cpabewaters11Instance.decrypt(messageAccess, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void test6() {
        CPABEWaters11 cpabewaters11Instance = new CPABEWaters11(20);
        cpabewaters11Instance.setUp("a.properties");

        int[] userAttributes = new int[]{1, 2, 3, 4};
        String skFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test6/sk.properties";
        cpabewaters11Instance.keyGeneration(userAttributes, skFilePath);

        CPABELewkoWatersLSSS.Node r = CPABELewkoWatersLSSSTest.getTree1();
        CPABELewkoWatersLSSS messageAccess = new CPABELewkoWatersLSSS(r, cpabewaters11Instance.getBp());
        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabewaters11Instance.getBp().getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        String ctFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test6/ct.properties";
        cpabewaters11Instance.encrypt(messageAccess, M, ctFilePath);

        Element M_  = cpabewaters11Instance.decrypt(messageAccess, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void test7() {
        CPABEWaters11 cpabewaters11Instance = new CPABEWaters11(20);
        cpabewaters11Instance.setUp("a.properties");

        int[] userAttributes = new int[]{2, 3, 4};
        String skFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test7/sk.properties";
        cpabewaters11Instance.keyGeneration(userAttributes, skFilePath);

        CPABELewkoWatersLSSS.Node r = CPABELewkoWatersLSSSTest.getTree1();
        CPABELewkoWatersLSSS messageAccess = new CPABELewkoWatersLSSS(r, cpabewaters11Instance.getBp());
        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabewaters11Instance.getBp().getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        String ctFilePath = "src/CPABE_Waters11/CPABEWatersFiles/test7/ct.properties";
        cpabewaters11Instance.encrypt(messageAccess, M, ctFilePath);

        Element M_  = cpabewaters11Instance.decrypt(messageAccess, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void main(String[] args) {
        test6();
    }
}
