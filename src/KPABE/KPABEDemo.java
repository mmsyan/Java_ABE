package KPABE;

import Utils.ConversionUtils;
import Utils.MathUtils;
import Utils.PropertiesUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Properties;

public class KPABEDemo {
    private int universe; // 属性宇宙的大小

    private Pairing bp; // 基于双线性对的密码学对象
    private Element g; // G1群的生成元

    private Element[] msk_ti; // 主密钥ti: Zr群的密钥元素数组
    private Element msk_y; // 主密钥y: Zr群的密钥元素

    private Element[] pk_Ti; // 公钥Ti: G1群的公钥元素数组
    private Element pk_Y; // 公钥Y: GT群的公钥元素

    public KPABEDemo(int u) {
        this.universe = u;
        this.msk_ti = new Element[u];
        this.pk_Ti = new Element[u];
    }

    /**
     * 初始化方法，用于设置双线性对参数并生成主密钥和公钥
     * KPABE的set up和FIBE的set up 如出一辙
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
        System.out.println("已成功初始化，属性大小为 " + universe);
    }

    /**
     * 加密方法，根据一组属性加密消息
     * @param messageAttributes 加密消息的属性数组
     * @param message 要加密的消息
     * @param ctFilePath 加密文本存储文件路径
     */
    public void encrypt(int[] messageAttributes, Element message, String ctFilePath) {
        Properties ctProperties = new Properties();
        ctProperties.setProperty("Message Attributes w' ", ConversionUtils.intArray2String(messageAttributes));

        Element s = bp.getZr().newRandomElement().getImmutable();
        // 生成密文E‘ = M * Y^s
        Element EPrime = message.mul(pk_Y.powZn(s)).getImmutable();
        ctProperties.setProperty("E' ", ConversionUtils.bytes2String(EPrime.toBytes()));
        // 生成密文Ei: i∈ω
        for (int i : messageAttributes) {
            Element Ei = pk_Ti[i].powZn(s).getImmutable();
            ctProperties.setProperty("E"+i, ConversionUtils.bytes2String(Ei.toBytes()));
        }
        PropertiesUtils.store(ctProperties, ctFilePath);
        System.out.println("已为密文属性 【" + ConversionUtils.intArray2String(messageAttributes) + "】 加密消息");
    }

    /**
     * 密钥生成方法，根据用户的属性访问控制树生成密钥。
     * @param userAttributes 用户的属性访问控制树
     * @param skFilePath 密钥存储文件路径
     */
    public void keyGeneration(KPABEAccessTree userAttributes, String skFilePath) {
        // 设置根节点的秘密值/多项式的常量/多项式在x=0处的取值
        userAttributes.generatePolySecret(this.bp, this.msk_y);

        Properties skProperties = new Properties();
        for (KPABEAccessTree.Node n : userAttributes) {
            if (n.isLeave()) {
                Element qx0 = MathUtils.qx(n.polynomial, bp.getZr().newElement(0));
                // 为用户访问控制树的每个叶子节点x生成对应的Dx(不是跟着属性i走！)
                Element D = this.g.powZn(qx0.div(this.msk_ti[n.attribute])).getImmutable();
                skProperties.setProperty("D" + n.leaveSequence, ConversionUtils.bytes2String(D.toBytes()));
            }
        }
        PropertiesUtils.store(skProperties, skFilePath);
    }

    /**
     * 解密方法，根据用户的属性访问控制树解密消息。
     * @param userAttributes 用户的属性访问控制树
     * @param skFilePath 密钥存储文件路径
     * @param ctFilePath 加密文本存储文件路径
     * @return 解密后的消息
     */
    public Element decrypt(KPABEAccessTree userAttributes, String skFilePath, String ctFilePath) {
        Properties ctProperties = PropertiesUtils.load(ctFilePath);
        int[] messageAttributes = ConversionUtils.String2intArray(ctProperties.getProperty("Message Attributes w' "));

        Properties skProperties = PropertiesUtils.load(skFilePath);
        String EPrimeStr = ctProperties.getProperty("E' ");
        Element EPrime = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(EPrimeStr)).getImmutable();

        // 解密需要准备好Ei和Di，这些都与属性对应
        HashMap<Integer, Element> ciphertextEi = new HashMap<>();
        HashMap<Integer, Element> secretKeyDi = new HashMap<>();
        for (int i = 0; i < universe; i++) {
            if (ctProperties.containsKey("E" + i)) {
                String EiStr = ctProperties.getProperty("E" + i);
                Element Ei = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(EiStr)).getImmutable();
                ciphertextEi.put(i, Ei);
            }
        }

        for (KPABEAccessTree.Node n : userAttributes) {
            if (n.isLeave()) {
                String DiStr = skProperties.getProperty("D" + n.leaveSequence);
                Element Di = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DiStr)).getImmutable();
                secretKeyDi.put(n.leaveSequence, Di);
            }
        }

        Element Ys = userAttributes.decryptNode(messageAttributes, secretKeyDi, ciphertextEi, bp);
        if (Ys != null) {
            System.out.println("密文属性和用户属性访问控制树匹配，解密成功！");
            return EPrime.div(Ys);
        }
        else {
            System.out.println("密文属性和用户属性访问控制树不匹配，解密失败！");
            return null;
        }
    }

    public static void testCase1() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEFile/sk.properties";
        String ctFilePath = "src/KPABE/KPABEFile/ct.properties";
        System.out.println("\n测试案例1：");
        // 初始化操作，设置属性上限为10
        KPABEDemo kpabeInstance = new KPABEDemo(10);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1, 2,  5}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        KPABEAccessTree tree1 = KPABEAccessTree.getInstance1();
        kpabeInstance.keyGeneration(tree1, skFilePath);

        Element M_ = kpabeInstance.decrypt(tree1, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase2() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEFile/sk.properties";
        String ctFilePath = "src/KPABE/KPABEFile/ct.properties";
        System.out.println("\n测试案例2：");
        // 初始化操作，设置属性上限为10
        KPABEDemo kpabeInstance = new KPABEDemo(20);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1, 3, 6}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        KPABEAccessTree tree2 = KPABEAccessTree.getInstance2();
        kpabeInstance.keyGeneration(tree2, skFilePath);

        Element M_ = kpabeInstance.decrypt(tree2, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }

    public static void testCase3() {
        //测试文件路径
        String skFilePath = "src/KPABE/KPABEFile/sk.properties";
        String ctFilePath = "src/KPABE/KPABEFile/ct.properties";
        System.out.println("\n测试案例3：");
        // 初始化操作，设置属性上限为10
        KPABEDemo kpabeInstance = new KPABEDemo(20);
        kpabeInstance.setUp("a.properties");

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = kpabeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        kpabeInstance.encrypt(new int[]{1, 3, 6}, M, ctFilePath);

        // 用户输入自己属性对应的访问控制树来生成密钥
        KPABEAccessTree userAttributes = KPABEAccessTree.getInstance3();
        kpabeInstance.keyGeneration(userAttributes, skFilePath);

        Element M_ = kpabeInstance.decrypt(userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }



    public static void main(String[] args) {
        testCase1();
        testCase2();
        testCase3();
    }
}
