package KPABE;

import Utils.ConversionUtils;
import Utils.MathUtils;
import Utils.PropertiesUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Properties;

/**
 * KPABE (Key-Policy Attribute Based Encryption) 演示类
 * 该类展示了KPABE属性加密方案的初始化、密钥生成、加密和解密过程。
 * Vipul Goyal, Omkant Pandey, Amit Sahai, and Brent Waters. 2006. Attribute-based encryption for fine-grained access control of encrypted data. In Proceedings of the 13th ACM conference on Computer and communications security (CCS '06). Association for Computing Machinery, New York, NY, USA, 89–98. https://doi.org/10.1145/1180405.1180418
 * 这个构造选自文章的第4.2节：Our Construction
 *
 * 作者: mmsyan
 * 完成时间: 2024-12-24
 * 参考文献: Attribute-based encryption for fine-grained access control of encrypted data
 */
public class KPABEa {
    private int universe; // 属性宇宙的大小，属性被预定义好为[1, 2, …… , Universe]
    private Pairing bp; // 基于双线性对的密码学对象
    private Element g; // G1群的生成元

    private Element[] msk_ti; // 主密钥ti: Zr群的密钥元素数组
    private Element msk_y; // 主密钥y: Zr群的密钥元素

    private Element[] pk_Ti; // 公钥Ti: G1群的公钥元素数组
    private Element pk_Y; // 公钥Y: GT群的公钥元素

    public KPABEa(int u) {
        this.universe = u;
        this.msk_ti = new Element[u+1];
        this.pk_Ti = new Element[u+1];
    }

    /**
     * 初始化方法，用于设置双线性对参数并生成主密钥和公钥
     * KPABEa的set up和FIBEa的set up 如出一辙
     * @param pairingFilePath 双线性对参数文件路径
     */
    public void setUp(String pairingFilePath) {
        bp = PairingFactory.getPairing(pairingFilePath);
        g = bp.getG1().newRandomElement().getImmutable();

        // 为每个属性生成主密钥和公钥。注意msk_ti[0]与pk_ti[0]是没有任何意义的。
        for (int i = 1; i <= universe; i++) {
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
        checkAttributeSet(messageAttributes);

        Properties ctProperties = new Properties();
        ctProperties.setProperty("Message Attributes w' ", ConversionUtils.intArray2String(messageAttributes));

        Element s = bp.getZr().newRandomElement().getImmutable();
        // 生成密文E‘ = M * Y^s
        Element EPrime = message.mul(pk_Y.powZn(s)).getImmutable();
        ctProperties.setProperty("E' ", ConversionUtils.bytes2String(EPrime.toBytes()));
        // 生成密文Ei: i∈ω, Ei = Ti^s
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
    public void keyGeneration(AccessTreeKPABE userAttributes, String skFilePath) {
        // 访问控制树操作：设置根节点的秘密值/多项式的常量/多项式在x=0处的取值
        userAttributes.generatePolySecret(this.bp, this.msk_y);

        // 生成密钥部分
        Properties skProperties = new Properties();
        for (AccessTreeKPABE.Node n : userAttributes) {
            if (n.isLeave()) {
                Element qx0 = MathUtils.qx(n.polynomial, bp.getZr().newElement(0));
                // 为用户访问控制树的每个叶子节点x生成对应的Dx(不是跟着属性i走！)
                // for each leaf node x: Dx = g^(qx0/ti) where i = attr(x)
                Element D = this.g.powZn(qx0.div(this.msk_ti[n.attribute])).getImmutable();
                skProperties.setProperty("D" + n.leafID, ConversionUtils.bytes2String(D.toBytes()));
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
    public Element decrypt(AccessTreeKPABE userAttributes, String skFilePath, String ctFilePath) {
        Properties ctProperties = PropertiesUtils.load(ctFilePath);
        int[] messageAttributes = ConversionUtils.String2intArray(ctProperties.getProperty("Message Attributes w' "));

        // 解密需要准备好E'
        Properties skProperties = PropertiesUtils.load(skFilePath);
        String EPrimeStr = ctProperties.getProperty("E' ");
        Element EPrime = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(EPrimeStr)).getImmutable();

        // 解密需要准备好Ei，这与属性对应。还需要准备好Di，这与叶子节点对应。
        HashMap<Integer, Element> ciphertextEi = new HashMap<>();
        HashMap<Integer, Element> secretKeyDi = new HashMap<>();
        for (int i : messageAttributes) {
            String EiStr = ctProperties.getProperty("E" + i);
            Element Ei = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(EiStr)).getImmutable();
            ciphertextEi.put(i, Ei);
        }

        for (AccessTreeKPABE.Node n : userAttributes) {
            if (n.isLeave()) {
                String DiStr = skProperties.getProperty("D" + n.leafID);
                Element Di = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DiStr)).getImmutable();
                secretKeyDi.put(n.leafID, Di);
            }
        }

        // 调用decryptNode(E, D, root)得到Y^s
        Element Ys = userAttributes.decryptNodeA(messageAttributes, secretKeyDi, ciphertextEi, bp);
        if (Ys != null) {
            System.out.println("密文设置的属性和用户属性访问控制树匹配，解密成功！");
            return EPrime.div(Ys);
        }
        else {
            System.out.println("密文设置的属性和用户属性访问控制树不匹配，解密失败！");
            return null;
        }
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
