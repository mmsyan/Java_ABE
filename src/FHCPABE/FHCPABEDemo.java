package FHCPABE;

import Utils.AESUtils;
import Utils.ConversionUtils;
import Utils.MathUtils;
import Utils.PropertiesUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import javax.crypto.SecretKey;
import java.io.File;
import java.util.Base64;
import java.util.HashMap;
import java.util.Properties;

/**
 * Xiao, M., Li, H., Huang, Q., Yu, S., & Susilo, W. (2022).
 * Attribute-Based Hierarchical Access Control With Extendable Policy.
 * IEEE Transactions on Information Forensics and Security, 17, 1868–1883.
 * <a href="https://doi.org/10.1109/tifs.2022.3173412">...</a>
 *
 * 2024.11.03，实现了setUp keyGeneration encrypt和decrypt四个步骤；尚没有完成exExtension和inExtension步骤
 * */
public class FHCPABEDemo {
    // 全局属性大小
    private int universe;

    // 双线性对相关参数：
    private Pairing bp;
    private Element g; //G1
    private Element alpha; //Zr
    private Element h; // h = g^beta;
    private Element msk_beta;  //Zr
    private Element msk_gAlpha;
    private Element eggAlpha;


    // 记载明文路径与密文路径匹配关系的映射；记载明文路径与解密后文件路径匹配关系的映射
    private HashMap<String, String> plainText2Ciphertext;
    private HashMap<String, String> plainText2DecryptedText;

    public FHCPABEDemo(int u, HashMap<String, String> m1, HashMap<String, String> m2) {
        this.universe = u;
        plainText2Ciphertext = m1;
        plainText2DecryptedText = m2;
    }

    // 初始化步骤，需要双线性对参数作为参数
    public void setUp(String pairingFilePath) {
        this.bp = PairingFactory.getPairing(pairingFilePath);
        this.g = bp.getG1().newRandomElement().getImmutable(); // g <- G1
        this.alpha = bp.getZr().newRandomElement().getImmutable(); // alpha <- Zr
        this.msk_beta = bp.getZr().newRandomElement().getImmutable(); // beta <- Zr
        this.h = this.g.powZn(this.msk_beta).getImmutable(); // h = g^beta
        this.msk_gAlpha = this.g.powZn(this.alpha).getImmutable();  // g^alpha
        this.eggAlpha = bp.pairing(g, g).powZn(alpha).getImmutable(); // e(g, g)^alpha
    }

    // 密钥生成步骤，需要用户属性和密钥文件存储地址作为参数
    public void keyGeneration(int[] userAttributes, String skFilePath) {
        Properties skProperties = new Properties();

        // r <- Zr; gR = g^r
        Element r = this.bp.getZr().newRandomElement().getImmutable();
        Element gR = this.g.powZn(r).getImmutable();

        // D = g^α * h^r = g^α * g^βr = g^(α+βr)
        Element D = msk_gAlpha.mul(h.powZn(r)).getImmutable();
        skProperties.setProperty("D", ConversionUtils.bytes2String(D.toBytes()));

        // for each attribute j ∈ S(user Attributes)
        for (int j : userAttributes) {
            Element rj = this.bp.getZr().newRandomElement().getImmutable(); // rj <- Zr
            Element hj = MathUtils.H1(String.valueOf(j), bp).getImmutable(); // H(i)
            Element hjRj = hj.powZn(rj).getImmutable(); // hiRi = H(i)^ri

            Element Dj = gR.mul(hjRj).getImmutable(); // Dj = g^r * H(j)^rj
            Element DjPrime = this.h.powZn(rj).getImmutable(); // Dj' = h^rj

            skProperties.setProperty("Dj"+j, ConversionUtils.bytes2String(Dj.toBytes()));
            skProperties.setProperty("DjPrime"+j, ConversionUtils.bytes2String(DjPrime.toBytes()));
        }
        PropertiesUtils.store(skProperties, skFilePath);
    }

    // 加密步骤，需要密文属性访问控制树，注意消息已经集成在访问控制树当中了
    public void encrypt(FHCPABEAccessTree messageAttributes, String ctFilePath) throws Exception {
        Properties ctProperties = new Properties();

        // 加密第一部分：生成ck={ck1, ck2, …… ckk}和s1 s2 …… sk in Zp
        Element[] ck = new Element[messageAttributes.k];
        Element[] s = new Element[messageAttributes.k];
        for (int i = 0; i < ck.length; i++) {
            ck[i] = bp.getGT().newRandomElement().getImmutable();
            s[i] = bp.getZr().newRandomElement().getImmutable();
        }

        for (FHCPABEAccessTree.Node n : messageAttributes) {
            if (n.isLevelNode()) {
                SecretKey Kx = AESUtils.generateSecretKey(ck[n.levelId-1].toBytes());
                // 打印加密阶段时恢复出来的密钥key
                System.out.println("加密阶段的密钥"+n.levelId+" : "+Base64.getEncoder().encodeToString(Kx.getEncoded()));
                File message = new File(n.filePath);
                File ciphertext = new File(plainText2Ciphertext.get(n.filePath));
                AESUtils.encrypt(message, ciphertext, Kx);
            }
        }

        // 加密第二部分：对于所有的层级节点i，生成CiWave和CiPrime。这是密文的一部分。
        for (int i = 1; i <= messageAttributes.k; i++) {
            Element CiWave = ck[i-1].mul(eggAlpha.powZn(s[i-1])).getImmutable(); //Ci~ = ck * (e(g, g)^alpha)^si
            Element CiPrime = g.powZn(s[i-1]).getImmutable(); // Ci' = g^si
            ctProperties.setProperty("CiWave"+i, ConversionUtils.bytes2String(CiWave.toBytes()));
            ctProperties.setProperty("CiPrime"+i, ConversionUtils.bytes2String(CiPrime.toBytes()));
        }

        // 加密第三部分：在给定的层级访问控制树上面自上而下的生成对应的多项式。注意，level node的多项式生成特殊一些；root必须是level node
        messageAttributes.generatePolySecret(bp, s);

        // 加密第四部分：对于所有叶子节点xy生成：Cxy Cxy'.对于所有传输节点x的孩子生成：C^x(j) Cx(2) Cx(3)
        for (FHCPABEAccessTree.Node n : messageAttributes) {
            // 叶子节点生成Cxy和Cxy'
            if (n.isLeave()) {
                int xyCount = n.id;
                Element Cxy = h.powZn(n.polynomial[0]).getImmutable();
                Element CxyPrime = (MathUtils.H1(String.valueOf(n.attribute), bp)).powZn(n.polynomial[0]);
                ctProperties.setProperty("Cxy"+xyCount, ConversionUtils.bytes2String(Cxy.toBytes()));
                ctProperties.setProperty("CxyPrime"+xyCount, ConversionUtils.bytes2String(CxyPrime.toBytes()));
            }
            // 传输节点的孩子节点生成需要的内容
            if (n.isTransparentNode()) {
                int xCount = n.id;
                Element q_xy_0 = n.polynomial[0];

                for (int j = 0; j < n.children.size(); j++) {
                    if (!n.children.get(j).isLeave()) {
                        Element CPower1 = eggAlpha.powZn((q_xy_0.add(n.children.get(j).polynomial[0]))).getImmutable();
                        //todo: FHCPABE_H2()没有实现
                        Element CPower2 = bp.pairing(g,g).powZn(alpha.mul(q_xy_0)).getImmutable();
                        Element CPower = CPower1.mul(CPower2);
                        ctProperties.setProperty("CPower_"+xCount+"_"+j, ConversionUtils.bytes2String(CPower.toBytes()));
                    }
                }
            }
        }
        PropertiesUtils.store(ctProperties, ctFilePath);
    }

    public void decrypt(FHCPABEAccessTree messageAttributes, int[] userAttributes, String skFilePath, String ctFilePath) throws Exception {
        Properties skProperties = PropertiesUtils.load(skFilePath);
        Properties ctProperties = PropertiesUtils.load(ctFilePath);

        // 解密需要准备好Di和Di'：这是与属性有关的解密项，是在密钥生成部分生成的内容。将其从密钥文件中恢复出来存储到secretKeyDi和secretKeyDiPrime中
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

        // 解密还需要准备好Cxy和Cxy'：这是与叶子节点是有关的，是在加密部分生成的内容。将其从密文文件中恢复出来存储到leaveNodeCxy和leaveNodeCxyPrime中
        HashMap<Integer, Element> leaveNodeCxy = new HashMap<>();
        HashMap<Integer, Element> leaveNodeCxyPrime = new HashMap<>();
        for (FHCPABEAccessTree.Node n : messageAttributes) {
            if (n.isLeave()) {
                int yCount = n.id;
                String CxyStr = ctProperties.getProperty(("Cxy"+yCount));
                Element Cxy = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CxyStr)).getImmutable();
                String CxyPrimeStr = ctProperties.getProperty("CxyPrime"+yCount);
                Element CxyPrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CxyPrimeStr)).getImmutable();
                leaveNodeCxy.put(yCount, Cxy);
                leaveNodeCxyPrime.put(yCount, CxyPrime);
            }
        }

        String DStr = skProperties.getProperty("D");
        Element D = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DStr)).getImmutable();

        for (FHCPABEAccessTree.Node n : messageAttributes) {
            if (n.isLevelNode()) {
                Element Ai = messageAttributes.decryptNode(n, userAttributes, secretKeyDj, secretKeyDjPrime, leaveNodeCxy, leaveNodeCxyPrime, bp).getImmutable();

                if (Ai != null) {
                    String CiPrimeStr = ctProperties.getProperty(("CiPrime"+n.levelId));
                    Element CiPrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CiPrimeStr)).getImmutable();

                    String CiWaveStr = ctProperties.getProperty(("CiWave"+n.levelId));
                    Element CiWave = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(CiWaveStr)).getImmutable();

                    Element Fi = bp.pairing(CiPrime, D).div(Ai).getImmutable();
                    Element cki = CiWave.div(Fi);

                    SecretKey Kx = AESUtils.generateSecretKey(cki.toBytes());
                    // 打印解密阶段时恢复出来的密钥key
                    System.out.println("解密阶段的密钥"+n.levelId+" : "+Base64.getEncoder().encodeToString(Kx.getEncoded()));

                    File ciphertext = new File(plainText2Ciphertext.get(n.filePath));
                    File decryptedText = new File(plainText2DecryptedText.get(n.filePath));
                    AESUtils.decrypt(ciphertext, decryptedText, Kx);
                }
                else {
                    System.out.println("密文属性和用户属性访问控制树不匹配，解密失败！");
                }
            }
        }

    }



    public static void testCase1() throws Exception {
        //测试文件路径
        String skFilePath = "src/FHCPABE/FHCPABEFile/test1/sk.properties";
        String ctFilePath = "src/FHCPABE/FHCPABEFile/test1/ct.properties";
        System.out.println("\n测试案例1：");
        // 初始化操作，设置属性上限为10

        HashMap<String, String> m1 = new HashMap<>();
        m1.put("src/FHCPABE/FHCPABEFile/test1/FileA.txt", "src/FHCPABE/FHCPABEFile/test1/CiphertextA.txt");
        m1.put("src/FHCPABE/FHCPABEFile/test1/FileB.txt", "src/FHCPABE/FHCPABEFile/test1/CiphertextB.txt");


        HashMap<String, String> m2 = new HashMap<>();
        m2.put("src/FHCPABE/FHCPABEFile/test1/FileA.txt", "src/FHCPABE/FHCPABEFile/test1/decryptedTextA.txt");
        m2.put("src/FHCPABE/FHCPABEFile/test1/FileB.txt", "src/FHCPABE/FHCPABEFile/test1/decryptedTextB.txt");


        FHCPABEDemo ehcpabeInstance = new FHCPABEDemo(10, m1, m2);
        ehcpabeInstance.setUp("a.properties");

        // 用户输入自己属性对应的访问控制树来生成密钥
        int[] userAttributes = new int[]{1, 2, 3, 4};
        ehcpabeInstance.keyGeneration(userAttributes, skFilePath);


        FHCPABEAccessTree tree1 = FHCPABEAccessTree.getInstance1();
        ehcpabeInstance.encrypt(tree1, ctFilePath);


        ehcpabeInstance.decrypt(tree1, userAttributes, skFilePath, ctFilePath);
    }




    public static void main(String[] args) throws Exception {
        testCase1();
    }
}
