package CPABE;

import Utils.ConversionUtils;
import Utils.MathUtils;
import Utils.PropertiesUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Properties;

/**
 * CPABE (Ciphertext-Policy Attribute Based Encryption) 演示类
 * 该类展示了CPABE属性加密方案的初始化、密钥生成、加密和解密过程。
 * J. Bethencourt, A. Sahai and B. Waters, "Ciphertext-Policy Attribute-Based Encryption," 2007 IEEE Symposium on Security and Privacy (SP '07), Berkeley, CA, USA, 2007, pp. 321-334, doi: 10.1109/SP.2007.11.
 * keywords: {Cryptography;Access control;Secure storage;Measurement;Personnel;File servers;Monitoring;Certification;Data security;Public key},
 * 这个构造选自文章的第4.2节：Our Construction
 *
 * 作者: mmsyan
 * 完成时间: 2024-12-25
 * 参考文献: Ciphertext-Policy Attribute-Based Encryption
 */
public class CPABE {
    private int universe;
    private Pairing bp;
    private Element g; //G1
    private Element alpha; //Zr
    private Element beta;  //Zr
    private Element h; // h = g^beta;
    private Element f;

    public CPABE(int u) {
        this.universe = u;
    }

    public void setUp(String pairingFilePath) {
        this.bp = PairingFactory.getPairing(pairingFilePath);
        this.g = bp.getG1().newRandomElement().getImmutable(); // g <- G1
        this.alpha = bp.getZr().newRandomElement().getImmutable(); // alpha <- Zr
        this.beta = bp.getZr().newRandomElement().getImmutable(); // beta <- Zr
        this.h = this.g.powZn(this.beta).getImmutable(); // h = g^beta
        this.f = this.g.powZn(bp.getZr().newOneElement().div(beta)).getImmutable();  // f = g^1/beta
    }

    public void keyGeneration(int[] userAttributes, String skFilePath) {
        checkAttributeSet(userAttributes);
        Properties skProperties = new Properties();

        Element r = this.bp.getZr().newRandomElement().getImmutable(); // r <- Zr
        Element gr = this.g.powZn(r).getImmutable();

        Element D = g.powZn((alpha.add(r)).div(beta)).getImmutable(); // D = g^((alpha+r)/beta) ∈ G1
        skProperties.setProperty("D", ConversionUtils.bytes2String(D.toBytes()));

        for (int j : userAttributes) { // for each attribute j ∈ S(user Attributes)
            Element rj = this.bp.getZr().newRandomElement().getImmutable(); // rj <- Zr
            Element hj = MathUtils.H1(String.valueOf(j), bp).getImmutable(); // H(j)
            Element hjrj = hj.powZn(rj).getImmutable(); // hjrj = H(j)^rj
            Element Dj = gr.mul(hjrj).getImmutable(); // Dj = g^r * H(j)^rj
            Element DjPrime = g.powZn(rj).getImmutable(); // Dj' = g^rj

            skProperties.setProperty("Dj"+j, ConversionUtils.bytes2String(Dj.toBytes()));
            skProperties.setProperty("DjPrime"+j, ConversionUtils.bytes2String(DjPrime.toBytes()));
        }

        PropertiesUtils.store(skProperties, skFilePath);
    }

    public void encrypt(AccessTreeCPABE messageAttributes, Element message, String ctFilePath) {
        Properties ctProperties = new Properties();

        Element s = bp.getZr().newRandomElement().getImmutable(); // s <- Zr
        messageAttributes.generatePolySecret(bp, s);

        Element CWave = message.mul((bp.pairing(g, g).powZn(alpha.mul(s))));
        Element C = h.powZn(s);
        ctProperties.setProperty("CWave", ConversionUtils.bytes2String(CWave.toBytes()));
        ctProperties.setProperty("C", ConversionUtils.bytes2String(C.toBytes()));

        for (AccessTreeCPABE.Node y : messageAttributes) {
            if (y.isLeave()) {
                int yCount = y.leafID;
                Element Cy = g.powZn(y.polynomial[0]).getImmutable();
                Element CyPrime = (MathUtils.H1(String.valueOf(y.attribute), bp)).powZn(y.polynomial[0]);
                ctProperties.setProperty("Cy"+yCount, ConversionUtils.bytes2String(Cy.toBytes()));
                ctProperties.setProperty("CyPrime"+yCount, ConversionUtils.bytes2String(CyPrime.toBytes()));
            }
        }

        PropertiesUtils.store(ctProperties, ctFilePath);
    }

    public Element decrypt(AccessTreeCPABE messageAttributes, int[] userAttributes, String skFilePath, String ctFilePath) {
        checkAttributeSet(userAttributes);
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
        for (AccessTreeCPABE.Node n : messageAttributes) {
            if (n.isLeave()) {
                int yCount = n.leafID;
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

    public void delegate(int[] userAttributes, int[] subSetUserAttributes, String skFilePath, String subSetSKFilePath) {
        checkAttributeSet(userAttributes);
        if (!MathUtils.isSubsetUsingSet(subSetUserAttributes, userAttributes)) {
            System.out.println("需要提供用户属性的子集合，你所提供的集合不在委托范围内！");
        }
        Properties skProperties = PropertiesUtils.load(skFilePath);
        Properties subSetProperties = new Properties();

        // r~ <- Zr; D~ = D*f^(r~)
        Element rWave = bp.getZr().newRandomElement();
        String DStr = skProperties.getProperty("D");
        Element D = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DStr));
        Element DWave = D.mul(f.powZn(rWave));
        subSetProperties.setProperty("D", ConversionUtils.bytes2String(DWave.toBytes()));

        for (int k : subSetUserAttributes) {
            Element rkWave = bp.getZr().newRandomElement().getImmutable();

            String DkStr = skProperties.getProperty("Dj"+k);
            Element Dk = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DkStr)).getImmutable();
            Element DkWave = Dk.mul(g.powZn(rWave)).mul((MathUtils.H1(String.valueOf(k), bp)).powZn(rkWave));
            subSetProperties.setProperty("Dj"+k, ConversionUtils.bytes2String(DkWave.toBytes()));

            String DkPrimeStr = skProperties.getProperty("DjPrime"+k);
            Element DkPrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DkPrimeStr)).getImmutable();
            Element DkWavePrime = DkPrime.mul(g.powZn(rkWave));
            subSetProperties.setProperty("DjPrime"+k, ConversionUtils.bytes2String(DkWavePrime.toBytes()));
        }

        PropertiesUtils.store(subSetProperties, subSetSKFilePath);
    }

    /**
     * 生成随机的明文，供后续的测试和验证使用。
     * @return 随机生成GT群中的元素作为明文
     */
    public Element generateRandomPlainText() {
        return this.bp.getGT().newRandomElement().getImmutable();
    }

    /**
     * 检查属性数组的合法性，确保所有属性都在有效范围内。
     * @param attributes 属性数组
     */
    private void checkAttributeSet(int[] attributes) {
        if (attributes == null || attributes.length == 0)
            throw new IllegalArgumentException("属性数组不能为空或无效");
        for (int a : attributes) {
            if (a < 1) throw new IllegalArgumentException("属性元素不能小于等于0");
            if (a > this.universe) throw new IllegalArgumentException("属性元素不能超过属性宇宙的范围");
        }
    }
}
