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
 * 该类展示了模糊属性加密方案的初始化、密钥生成、加密和解密过程。
 *
 * 作者: mmsyan
 * 完成时间: 2024-12-18
 * 参考文献: Fuzzy Identity-Based Encryption
 */
public class FIBE {
    private final int universe; // 属性宇宙的大小，表示所有可能的属性集合的大小
    private final int distance; // 加密方案的容错距离，控制解密时要求的最小匹配度

    private Pairing bp; // 基于双线性对的密码学对象
    private Element g; // G1群的生成元

    private Element[] msk_ti; // 主密钥ti: Zr群的密钥元素数组
    private Element msk_y; // 主密钥y: Zr群的密钥元素

    private Element[] pk_Ti; // 公钥Ti: G1群的公钥元素数组
    private Element pk_Y; // 公钥Y: GT群的公钥元素

    /**
     * 构造函数，用于初始化FIBEDemo类
     * @param u 属性宇宙的大小，u代表属性可以选取[0, 1, …… , u-1]
     * @param d 加密方案的容错距离，用户属性和密文属性的交集不小于容错距离时可以成功解密
     */
    public FIBE(int u, int d) {
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
        // 校验用户属性的合法性
        checkAttributeSet(userAttributes);

        // 生成随机多项式q(x)用于加密计算。q(0)=y
        Element[] q = MathUtils.generateRandomPolynomial(distance, msk_y, bp);

        // 存储用户私钥的属性文件
        Properties skProperties = new Properties();

        // 为用户的每个属性生成对应的私钥
        for (int i : userAttributes) {
            Element ti = msk_ti[i]; // 获取属性对应的私钥ti
            Element qi = MathUtils.qx(q, bp.getZr().newElement(i)); // 计算q(i)
            Element Di = g.powZn(qi.div(ti)).getImmutable(); // 计算Di = g^(q(i)/ti)

            // 将私钥保存到属性文件中
            skProperties.setProperty("Attribute" + i, ConversionUtils.bytes2String(Di.toBytes()));
        }

        // 将私钥属性文件保存到指定路径
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
        // 校验消息属性的合法性
        checkAttributeSet(messageAttributes);

        // 存储密文的属性文件:ω' message attributes
        Properties ctProperties = new Properties();

        // 保存加密消息的属性信息
        ctProperties.setProperty("Message Attributes ω' ", ConversionUtils.intArray2String(messageAttributes));

        // 随机生成一个元素s用于加密
        Element s = bp.getZr().newRandomElement().getImmutable();

        // 计算加密后的密文组件 E' = M * Y^s
        Element EPrime = message.mul(pk_Y.powZn(s)).getImmutable();
        ctProperties.setProperty("E' ", ConversionUtils.bytes2String(EPrime.toBytes()));

        // 为每个消息属性计算对应的密文组件Ei
        for (int i : messageAttributes) {
            Element Ei = pk_Ti[i].powZn(s).getImmutable();
            ctProperties.setProperty("E" + i, ConversionUtils.bytes2String(Ei.toBytes()));
        }

        // 将加密后的属性信息保存到文件中
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
        // 校验用户属性的合法性
        checkAttributeSet(userAttributes);

        // 加载密文属性
        Properties ctProperties = PropertiesUtils.load(ctFilePath);
        int[] messageAttributes = ConversionUtils.String2intArray(ctProperties.getProperty("Message Attributes ω' "));

        // 如果用户属性和消息属性的交集大小不够容错距离，则解密失败
        // // if |ω ∩ ω′| ≥ d, Choose an arbitrary d-element subset S ⊂ (ω ∩ ω′)
        int[] S = MathUtils.findCommonAttributes(userAttributes, messageAttributes, distance);
        if (S == null) {
            System.out.println("用户的属性与消息的属性匹配度不够，解密失败！");
            return null;
        }

        // 解密步骤
        Properties skProperties = PropertiesUtils.load(skFilePath);
        String EPrimeStr = ctProperties.getProperty("E' ");
        Element EPrime = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(EPrimeStr)).getImmutable();

        // 初始化分母元素为1
        Element denominator = bp.getGT().newOneElement().getImmutable();

        // 计算Lagrange基并累乘相应的e(Di, Ei)^delta项
        for (int i : S) {
            String DiStr = skProperties.getProperty("Attribute" + i);
            Element Di = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DiStr)).getImmutable();
            String EiStr = ctProperties.getProperty("E" + i);
            Element Ei = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(EiStr)).getImmutable();

            Element delta = MathUtils.computeLagrangeBasis(i, S, 0, bp);
            denominator = denominator.mul(bp.pairing(Di, Ei).powZn(delta)); // 计算分母项
        }

        // 最终解密得到的消息
        Element decryptedMessage = EPrime.div(denominator);
        System.out.println("解密成功。解密得到的消息: " + decryptedMessage);
        return decryptedMessage;
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
            if (a < 0) throw new IllegalArgumentException("属性元素不能小于0");
            if (a >= this.universe) throw new IllegalArgumentException("属性元素不能大于或等于属性宇宙的大小");
        }
    }
}