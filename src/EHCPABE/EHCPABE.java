package EHCPABE;

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
 * https://doi.org/10.1109/tifs.2022.3173412
 *
 * 2024.11.03，实现了setUp keyGeneration encrypt和decrypt四个步骤；尚没有完成exExtension和inExtension步骤
 * */
public class EHCPABE {
    // 全局属性大小
    private int universe;

    // 双线性对相关参数：
    private Pairing bp;
    private Element g; //G1
    private Element alpha; //Zr
    private Element h; // h = g^beta;
    private Element msk_beta;  //Zr
    private Element msk_gAlpha;

    // 记载明文路径与密文路径匹配关系的映射；记载明文路径与解密后文件路径匹配关系的映射
    private HashMap<String, String> plainText2Ciphertext;
    private HashMap<String, String> plainText2DecryptedText;

    public EHCPABE(int u, HashMap<String, String> m1, HashMap<String, String> m2) {
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
    }

    // 密钥生成步骤，需要用户属性和密钥文件存储地址作为参数
    public void keyGeneration(int[] userAttributes, String skFilePath) {
        Properties skProperties = new Properties();

        // r <- Zr; gR = g^r
        Element r = this.bp.getZr().newRandomElement().getImmutable();
        Element gR = this.g.powZn(r).getImmutable();

        // D = g^α * h^r
        Element D = msk_gAlpha.mul(h.powZn(r)).getImmutable();
        skProperties.setProperty("D", ConversionUtils.bytes2String(D.toBytes()));

        // for each attribute j ∈ S(user Attributes)
        for (int i : userAttributes) {
            Element ri = this.bp.getZr().newRandomElement().getImmutable(); // rj <- Zr
            Element hi = MathUtils.H1(String.valueOf(i), bp).getImmutable(); // H(i)
            Element hiRi = hi.powZn(ri).getImmutable(); // hiRi = H(i)^ri

            Element Di = gR.mul(hiRi).getImmutable(); // Di = g^r * H(i)^ri
            Element DiPrime = this.h.powZn(ri).getImmutable(); // Di' = h^ri

            skProperties.setProperty("Di"+i, ConversionUtils.bytes2String(Di.toBytes()));
            skProperties.setProperty("DiPrime"+i, ConversionUtils.bytes2String(DiPrime.toBytes()));
        }

        PropertiesUtils.store(skProperties, skFilePath);
    }

    // 加密步骤，需要密文属性访问控制树，注意消息已经集成在访问控制树当中了
    public void encrypt(AccessTreeEHCPABE messageAttributes, String ctFilePath) throws Exception {
        Properties ctProperties = new Properties();

        // 加密第一部分：在给定的层级访问控制树上面自上而下的生成对应的多项式
        Element qA_0 = bp.getZr().newRandomElement().getImmutable(); // s <- Zr
        messageAttributes.generatePolySecret(bp, qA_0);

        // 加密第二部分：对于所有非叶子节点x生成：Cx(1) Cx(2) Cx(3)。对于所有叶子节点y生成：Cy Cy'
        for (AccessTreeEHCPABE.Node n : messageAttributes) {
            if (n.isLeave()) {
                int yCount = n.id;
                Element Cy = h.powZn(n.polynomial[0]).getImmutable();
                Element CyPrime = (MathUtils.H1(String.valueOf(n.attribute), bp)).powZn(n.polynomial[0]);
                ctProperties.setProperty("Cy"+yCount, ConversionUtils.bytes2String(Cy.toBytes()));
                ctProperties.setProperty("CyPrime"+yCount, ConversionUtils.bytes2String(CyPrime.toBytes()));
            }
            else {
                int xCount = n.id;
                Element Rx = bp.getGT().newRandomElement().getImmutable();
                Element C1x = Rx.mul(bp.pairing(g.powZn(alpha), g.powZn(n.polynomial[0]))).getImmutable();
                Element C2x = g.powZn(n.polynomial[0]);
                SecretKey Kx = AESUtils.generateSecretKey(MathUtils.EHCPABE_H2(C1x, C2x, Rx));
                // 打印加密阶段时恢复出来的密钥key
                System.out.println("加密阶段的密钥"+n.id+" : "+Base64.getEncoder().encodeToString(Kx.getEncoded()));


                if (n.filePath != null) {
                    File message = new File(n.filePath);
                    File ciphertext = new File(plainText2Ciphertext.get(n.filePath));
                    AESUtils.encrypt(message, ciphertext, Kx);
                }
                ctProperties.setProperty("C1x"+xCount, ConversionUtils.bytes2String(C1x.toBytes()));
                ctProperties.setProperty("C2x"+xCount, ConversionUtils.bytes2String(C2x.toBytes()));
            }
        }

        PropertiesUtils.store(ctProperties, ctFilePath);
    }

    public void decrypt(AccessTreeEHCPABE messageAttributes, int[] userAttributes, String skFilePath, String ctFilePath) throws Exception {
        Properties skProperties = PropertiesUtils.load(skFilePath);
        Properties ctProperties = PropertiesUtils.load(ctFilePath);

        // 解密需要准备好Di和Di'：这是与属性有关的解密项，是在密钥生成部分生成的内容。将其从密钥文件中恢复出来存储到secretKeyDi和secretKeyDiPrime中
        HashMap<Integer, Element> secretKeyDi = new HashMap<>();
        HashMap<Integer, Element> secretKeyDiPrime = new HashMap<>();
        for (int i = 0; i < universe; i++) {
            if (skProperties.containsKey("Di"+i)) {
                String DiStr = skProperties.getProperty("Di"+i);
                Element Di = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DiStr)).getImmutable();
                secretKeyDi.put(i, Di);
            }
            if (skProperties.containsKey("DiPrime"+i)) {
                String DiPrimeStr = skProperties.getProperty("DiPrime"+i);
                Element DiPrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DiPrimeStr)).getImmutable();
                secretKeyDiPrime.put(i, DiPrime);
            }
        }

        // 解密还需要准备好Cy和Cy'：这是与叶子节点是有关的，是在加密部分生成的内容。将其从密文文件中恢复出来存储到leaveNodeCy和leaveNodeCyPrime中
        HashMap<Integer, Element> leaveNodeCy = new HashMap<>();
        HashMap<Integer, Element> leaveNodeCyPrime = new HashMap<>();
        for (AccessTreeEHCPABE.Node n : messageAttributes) {
            if (n.isLeave()) {
                int yCount = n.id;
                String CyStr = ctProperties.getProperty(("Cy"+yCount));
                Element Cy = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CyStr)).getImmutable();
                String CyPrimeStr = ctProperties.getProperty("CyPrime"+yCount);
                Element CyPrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CyPrimeStr)).getImmutable();
                leaveNodeCy.put(yCount, Cy);
                leaveNodeCyPrime.put(yCount, CyPrime);
            }
        }

        String DStr = skProperties.getProperty("D");
        Element D = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DStr)).getImmutable();

        for (AccessTreeEHCPABE.Node n : messageAttributes) {
            if (!n.isLeave() && n.filePath != null) {
                String C1xStr = ctProperties.getProperty("C1x"+n.id);
                Element C1x = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(C1xStr)).getImmutable();
                String C2xStr = ctProperties.getProperty("C2x"+n.id);
                Element C2x = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(C2xStr)).getImmutable();

                Element decNode = messageAttributes.decryptNode(n, userAttributes, secretKeyDi, secretKeyDiPrime, leaveNodeCy, leaveNodeCyPrime, bp);
                if (decNode != null) {
                    System.out.println("密文属性和用户属性访问控制树匹配，解密成功！");
                    Element Rx = C1x.div((bp.pairing(C2x, D)).div(decNode));

                    SecretKey Kx = AESUtils.generateSecretKey(MathUtils.EHCPABE_H2(C1x, C2x, Rx));

                    // 打印解密阶段时恢复出来的密钥key
                    System.out.println("解密阶段的密钥"+n.id+" : "+Base64.getEncoder().encodeToString(Kx.getEncoded()));

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









}
