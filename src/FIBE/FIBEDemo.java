package FIBE;

import Utils.PropertiesUtils;
import Utils.ConversionUtils;
import Utils.MathUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Properties;

/**
 * FIBE (Fuzzy Identity Based Encryption) 演示类
 * 该类展示了FIBE加密方案的初始化、密钥生成、加密和解密过程。
 */
public class FIBEDemo {
    private int universe; // 属性宇宙的大小
    private int distance; // 加密方案的参数距离

    private Pairing bp; // 基于双线性对的密码学对象
    private Element g; // G1群的生成元

    private Element[] msk_ti; // 主密钥ti: Zr群的密钥元素数组
    private Element msk_y; // 主密钥y: Zr群的密钥元素

    private Element[] pk_Ti; // 公钥Ti: G1群的公钥元素数组
    private Element pk_Y; // 公钥Y: GT群的公钥元素

    /**
     * 构造函数，用于初始化FIBEDemo类
     * @param u 属性宇宙的大小
     * @param d 加密方案的参数距离
     */
    public FIBEDemo(int u, int d) {
        this.universe = u;
        this.distance = d;
        msk_ti = new Element[u]; // Zr类型元素数组
        pk_Ti = new Element[u]; // G1类型元素数组
    }

    /**
     * 初始化方法，用于设置双线性对参数并生成主密钥和公钥
     * @param pairingFilePath 双线性对参数文件路径
     */
    public void setUp(String pairingFilePath) {
        bp = PairingFactory.getPairing(pairingFilePath);
        g = bp.getG1().newRandomElement().getImmutable();

        // 为每个属性生成主密钥和公钥
        for (int i = 0; i < universe; i++) {
            msk_ti[i] = bp.getZr().newRandomElement().getImmutable(); // msk: t1 t2 …… tu <- Zr
            pk_Ti[i] = g.powZn(msk_ti[i]).getImmutable(); // PK: g^t1, g^t2, ……, g^tu ∈ G1
        }
        msk_y = bp.getZr().newRandomElement().getImmutable(); // msk: y <- Zr
        pk_Y = bp.pairing(g, g).powZn(msk_y).getImmutable(); // PK: Y = e(g, g)^y ∈ GT
        System.out.println("已成功初始化，属性大小为 " + universe + "，容错距离为 " + distance);
    }

    /**
     * 密钥生成方法，根据用户的属性生成用户的密钥
     * @param userAttributes 用户的属性数组
     * @param skFilePath 密钥存储文件路径
     */
    public void keyGeneration(int[] userAttributes, String skFilePath) {
        Element[] q = MathUtils.generateRandomPolynomial(distance, msk_y, bp); // q(x) = …… , q(0) = y

        Properties skProperties = new Properties();
        for (int i : userAttributes) {
            Element ti = msk_ti[i];
            Element qi = MathUtils.qx(q, bp.getZr().newElement(i)); // qi = q(i)
            Element Di = g.powZn(qi.div(ti)).getImmutable(); // Di = g^(qi/ti) ∈ G1
            String key = "Attribute" + i;
            skProperties.setProperty(key, ConversionUtils.bytes2String(Di.toBytes()));
        }
        PropertiesUtils.store(skProperties, skFilePath);
        System.out.println("已为用户属性 【" + ConversionUtils.intArray2String(userAttributes) + "】 生成密钥");
    }

    /**
     * 加密方法，根据一组属性加密消息
     * @param messageAttributes 加密消息的属性数组
     * @param message 要加密的消息,m ∈ G2
     * @param ctFilePath 加密文本存储文件路径
     */
    public void encrypt(int[] messageAttributes, Element message, String ctFilePath) {
        Properties ctProperties = new Properties(); // ω' : message attributes
        ctProperties.setProperty("Message Attributes w' ", ConversionUtils.intArray2String(messageAttributes));

        Element s = bp.getZr().newRandomElement().getImmutable(); // s <- Zr
        Element EPrime = message.mul(pk_Y.powZn(s)).getImmutable(); // E‘ = M * Y^s ∈ Gt
        ctProperties.setProperty("E' ", ConversionUtils.bytes2String(EPrime.toBytes()));

        for (int i : messageAttributes) {
            Element Ei = pk_Ti[i].powZn(s).getImmutable(); // Ei = Ti^s ∈ G1
            ctProperties.setProperty("E"+i, ConversionUtils.bytes2String(Ei.toBytes()));
        }

        PropertiesUtils.store(ctProperties, ctFilePath);
        System.out.println("已为消息属性 【" + ConversionUtils.intArray2String(messageAttributes) + "】 加密消息");
    }

    /**
     * 解密方法，根据用户的属性解密密文
     * @param userAttributes 用户的属性数组
     * @param skFilePath 用户密钥文件路径
     * @param ctFilePath 密文文件路径
     * @return 解密得到的消息
     */
    public Element decrypt(int[] userAttributes, String skFilePath, String ctFilePath) {
        Properties ctProperties = PropertiesUtils.load(ctFilePath);
        int[] messageAttributes = ConversionUtils.String2intArray(ctProperties.getProperty("Message Attributes w' "));

        // if |ω ∩ ω′| ≥ d, Choose an arbitrary d-element subset S ⊂ (ω ∩ ω′)
        int[] S = MathUtils.findCommonAttributes(userAttributes, messageAttributes, distance);
        if (S == null) {
            System.out.println("用户的属性与消息的属性匹配度不够，解密失败！");
            return null;
        }

        // E' = M * Y^s ∈ Gt
        Properties skProperties = PropertiesUtils.load(skFilePath);
        String EPrimeStr = ctProperties.getProperty("E' ");
        Element EPrime = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(EPrimeStr)).getImmutable();

        // delta = 1
        Element denominator = bp.getGT().newOneElement().getImmutable();
        for (int i : S) {
            String DiStr = skProperties.getProperty("Attribute" + i);
            Element Di = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DiStr)).getImmutable();
            String EiStr = ctProperties.getProperty("E"+i);
            Element Ei = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(EiStr)).getImmutable();

            Element delta = MathUtils.computeLagrangeBasis(i, S, 0, bp);
            denominator = denominator.mul(bp.pairing(Di, Ei).powZn(delta)); // ∏ e(Di, Ei)^delta
        }
        Element decryptedMessage = EPrime.div(denominator);
        System.out.println("解密成功。解密得到的消息: " + decryptedMessage);
        return decryptedMessage;
    }

    public static void testCase1() {
        String skFilePath = "src/FIBE/FIBEFile/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/ct.properties";

        System.out.println("\n测试案例1：");
        FIBEDemo fibeInstance = new FIBEDemo(10, 3);
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{1, 2, 3, 4}, skFilePath);
        Element M = fibeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("测试案例1中M 是 " + M);
        fibeInstance.encrypt(new int[]{2, 3, 4, 5}, M, ctFilePath);
        Element M_ = fibeInstance.decrypt(new int[]{1, 2, 3, 4}, skFilePath, ctFilePath);
        System.out.println("测试案例1中M_ 是 " + M_);
    }

    public static void testCase2() {
        String skFilePath = "src/FIBE/FIBEFile/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/ct.properties";

        System.out.println("\n测试案例2：");
        FIBEDemo anotherInstance = new FIBEDemo(5, 2);
        anotherInstance.setUp("a.properties");
        anotherInstance.keyGeneration(new int[]{0, 2, 4}, skFilePath);
        Element anotherM = anotherInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("测试案例2中M 是 " + anotherM);
        anotherInstance.encrypt(new int[]{1, 2, 3}, anotherM, ctFilePath);
        Element anotherM_ = anotherInstance.decrypt(new int[]{0, 2, 4}, skFilePath, ctFilePath);
        System.out.println("测试案例2中M_ 是 " + anotherM_);
    }

    /**
     * 测试案例3：测试更大的属性宇宙和不同的参数距离
     */
    public static void testCase3() {
        String skFilePath = "src/FIBE/FIBEFile/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/ct.properties";

        System.out.println("\n测试案例3：");
        FIBEDemo fibeInstance = new FIBEDemo(20, 5);
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{0, 5, 6, 10, 11, 15}, skFilePath);
        Element M = fibeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("测试案例3中M 是 " + M);
        fibeInstance.encrypt(new int[]{0, 5, 6, 8, 11, 15, 16}, M, ctFilePath);
        Element M_ = fibeInstance.decrypt(new int[]{0, 5, 6, 10, 11, 15}, skFilePath, ctFilePath);
        System.out.println("测试案例3中M_ 是 " + M_);
    }

    /**
     * 测试案例4：测试属性宇宙大小为奇数的情况
     */
    public static void testCase4() {
        String skFilePath = "src/FIBE/FIBEFile/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/ct.properties";

        System.out.println("\n测试案例4：");
        FIBEDemo fibeInstance = new FIBEDemo(11, 3);
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{1, 3, 6, 9}, skFilePath);
        Element M = fibeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("测试案例4中M 是 " + M);
        fibeInstance.encrypt(new int[]{2, 4, 7, 10}, M, ctFilePath);
        Element M_ = fibeInstance.decrypt(new int[]{1, 3, 6, 9}, skFilePath, ctFilePath);
        System.out.println("测试案例4中M_ 是 " + M_);
    }

    /**
     * 测试案例5：测试属性宇宙大小为1的情况
     */
    public static void testCase5() {
        String skFilePath = "src/FIBE/FIBEFile/sk.properties";
        String ctFilePath = "src/FIBE/FIBEFile/ct.properties";

        System.out.println("\n测试案例5：");
        FIBEDemo fibeInstance = new FIBEDemo(1, 1);
        fibeInstance.setUp("a.properties");
        fibeInstance.keyGeneration(new int[]{0}, skFilePath);
        Element M = fibeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("测试案例5中M 是 " + M);
        fibeInstance.encrypt(new int[]{0}, M, ctFilePath);
        Element M_ = fibeInstance.decrypt(new int[]{0}, skFilePath, ctFilePath);
        System.out.println("测试案例5中M_ 是 " + M_);
    }

    /**
     * 主方法，用于演示FIBE加密方案
     * @param args 命令行参数
     * @throws Exception 如果在加密或解密过程中发生错误
     */
    public static void main(String[] args) throws Exception {
        testCase1();
        testCase2();
        testCase3();
        testCase4();
        testCase5();
    }
}