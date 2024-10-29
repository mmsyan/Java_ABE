package EHCPABE;

import CPABE.CPABEAccessTree;
import Utils.ConversionUtils;
import Utils.MathUtils;
import Utils.PropertiesUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Properties;

public class EHCPABEDemo {
    private int universe;
    private Pairing bp;
    private Element g; //G1
    private Element alpha; //Zr
    private Element beta;  //Zr
    private Element h; // h = g^beta;
    private Element gAlpha;

    public EHCPABEDemo(int u) {
        this.universe = u;
    }

    public void setUp(String pairingFilePath) {
        this.bp = PairingFactory.getPairing(pairingFilePath);
        this.g = bp.getG1().newRandomElement().getImmutable(); // g <- G1
        this.alpha = bp.getZr().newRandomElement().getImmutable(); // alpha <- Zr
        this.beta = bp.getZr().newRandomElement().getImmutable(); // beta <- Zr
        this.h = this.g.powZn(this.beta).getImmutable(); // h = g^beta
        this.gAlpha = this.g.powZn(this.alpha).getImmutable();  // g^alpha
    }

    public void keyGeneration(int[] userAttributes, String skFilePath) {
        Properties skProperties = new Properties();

        Element r = this.bp.getZr().newRandomElement().getImmutable(); // r <- Zr
        Element gr = this.g.powZn(r).getImmutable();

        Element D = gAlpha.mul(h.powZn(r)).getImmutable(); // D = g^α * h^r
        skProperties.setProperty("D", ConversionUtils.bytes2String(D.toBytes()));

        for (int i : userAttributes) { // for each attribute j ∈ S(user Attributes)
            Element ri = this.bp.getZr().newRandomElement().getImmutable(); // rj <- Zr

            Element hi = MathUtils.H1(String.valueOf(i), bp).getImmutable(); // H(i)
            Element hiri = hi.powZn(ri).getImmutable(); // hiri = H(i)^ri

            Element Di = gr.mul(hiri).getImmutable(); // Di = g^r * H(i)^ri
            Element DiPrime = this.h.powZn(ri).getImmutable(); // Di' = h^ri

            skProperties.setProperty("Di"+i, ConversionUtils.bytes2String(Di.toBytes()));
            skProperties.setProperty("DiPrime"+i, ConversionUtils.bytes2String(DiPrime.toBytes()));
        }

        PropertiesUtils.store(skProperties, skFilePath);
    }

    public void encrypt(CPABEAccessTree messageAttributes, Element message, String ctFilePath) {
        Properties ctProperties = new Properties();

        Element s = bp.getZr().newRandomElement().getImmutable(); // s <- Zr
        messageAttributes.generatePolySecret(bp, s);

        Element CWave = message.mul((bp.pairing(g, g).powZn(alpha.mul(s))));
        Element C = h.powZn(s);
        ctProperties.setProperty("CWave", ConversionUtils.bytes2String(CWave.toBytes()));
        ctProperties.setProperty("C", ConversionUtils.bytes2String(C.toBytes()));

        for (CPABEAccessTree.Node y : messageAttributes) {
            if (y.isLeave()) {
                int yCount = y.leaveSequence;
                Element Cy = g.powZn(y.polynomial[0]).getImmutable();
                Element CyPrime = (MathUtils.H1(String.valueOf(y.attribute), bp)).powZn(y.polynomial[0]);
                ctProperties.setProperty("Cy"+yCount, ConversionUtils.bytes2String(Cy.toBytes()));
                ctProperties.setProperty("CyPrime"+yCount, ConversionUtils.bytes2String(CyPrime.toBytes()));
            }
        }

        PropertiesUtils.store(ctProperties, ctFilePath);
    }

    public Element decrypt(CPABEAccessTree messageAttributes, int[] userAttributes, String skFilePath, String ctFilePath) {
        Properties skProperties = PropertiesUtils.load(skFilePath);
        Properties ctProperties = PropertiesUtils.load(ctFilePath);

        // 解密需要准备好Dj和Dj'：这与属性是有关的
        HashMap<Integer, Element> secretKeyDj = new HashMap<>();
        HashMap<Integer, Element> secretKeyDjPrime = new HashMap<>();
        for (int j = 0; j < universe; j++) {
            if (skProperties.containsKey("Dj"+j)) {
                String DjStr = skProperties.getProperty("Dj"+j);
                Element Dj = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DjStr)).getImmutable();
                secretKeyDj.put(j, Dj);
            }
            if (skProperties.containsKey("DjPrime"+j)) {
                String DjPrimeStr = skProperties.getProperty("DjPrime"+j);
                Element DjPrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DjPrimeStr)).getImmutable();
                secretKeyDjPrime.put(j, DjPrime);
            }
        }

        // 解密还需要准备好Cy和Cy'：这与叶子节点是有关的
        HashMap<Integer, Element> leaveNodeCy = new HashMap<>();
        HashMap<Integer, Element> leaveNodeCyPrime = new HashMap<>();
        for (CPABEAccessTree.Node n : messageAttributes) {
            if (n.isLeave()) {
                int yCount = n.leaveSequence;
                String CyStr = ctProperties.getProperty(("Cy"+yCount));
                Element Cy = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CyStr)).getImmutable();
                String CyPrimeStr = ctProperties.getProperty("CyPrime"+yCount);
                Element CyPrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CyPrimeStr)).getImmutable();
                leaveNodeCy.put(yCount, Cy);
                leaveNodeCyPrime.put(yCount, CyPrime);
            }
        }

        String CWaveStr = ctProperties.getProperty(("CWave"));
        Element CWave = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(CWaveStr)).getImmutable();

        // 解密还需要C和D
        String DStr = skProperties.getProperty("D");
        Element D = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DStr)).getImmutable();
        String CStr = ctProperties.getProperty("C");
        Element C = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CStr)).getImmutable();


        Element A = messageAttributes.decryptNode(userAttributes, secretKeyDj, secretKeyDjPrime, leaveNodeCy, leaveNodeCyPrime, bp);
        if (A != null) {
            System.out.println("密文属性和用户属性访问控制树匹配，解密成功！");
            return CWave.div((bp.pairing(C, D)).div(A));
        }
        else {
            System.out.println("密文属性和用户属性访问控制树不匹配，解密失败！");
            return null;
        }
    }



    public static void testCase1() {
        //测试文件路径
        String skFilePath = "src/CPABE/CPABEFile/test1/sk.properties";
        String ctFilePath = "src/CPABE/CPABEFile/test1/ct.properties";
        System.out.println("\n测试案例1：");
        // 初始化操作，设置属性上限为10
        EHCPABEDemo cpabeInstance = new EHCPABEDemo(10);
        cpabeInstance.setUp("a.properties");

        // 用户输入自己属性对应的访问控制树来生成密钥
        int[] userAttributes = new int[]{1, 2, 5};
        cpabeInstance.keyGeneration(userAttributes, skFilePath);

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        CPABEAccessTree tree1 = CPABEAccessTree.getInstance1();
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
        EHCPABEDemo cpabeInstance = new EHCPABEDemo(20);
        cpabeInstance.setUp("a.properties");

        // 用户输入自己属性对应的访问控制树来生成密钥
        int[] userAttributes = new int[]{1, 3, 6};
        cpabeInstance.keyGeneration(userAttributes, skFilePath);

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        CPABEAccessTree messageAttributes = CPABEAccessTree.getInstance2();
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
        EHCPABEDemo cpabeInstance = new EHCPABEDemo(20);
        cpabeInstance.setUp("a.properties");

        // 用户输入自己属性对应的访问控制树来生成密钥
        int[] userAttributes = new int[]{1, 3, 6};
        cpabeInstance.keyGeneration(userAttributes, skFilePath);

        // 随机选取Gt上的元素作为消息并打印出来
        Element M = cpabeInstance.bp.getGT().newRandomElement().getImmutable();
        System.out.println("M 是 " + M);
        CPABEAccessTree messageAttributes = CPABEAccessTree.getInstance3();
        cpabeInstance.encrypt(messageAttributes, M, ctFilePath);


        Element M_ = cpabeInstance.decrypt(messageAttributes, userAttributes, skFilePath, ctFilePath);
        System.out.println("M_ 是 " + M_);
    }



    public static void main(String[] args) {
        testCase1();
        testCase2();
        testCase3();
    }
}
