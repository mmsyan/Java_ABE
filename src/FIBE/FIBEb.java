package FIBE;

import Utils.ConversionUtils;
import Utils.MathUtils;
import Utils.PropertiesUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Properties;

/**
 * FIBE (Fuzzy Identity Based Encryption) 演示类
 * 该类展示了模糊属性加密方案的初始化、密钥生成、加密和解密过程。
 * Sahai, A., Waters, B. (2005). Fuzzy Identity-Based Encryption. In: Cramer, R. (eds) Advances in Cryptology – EUROCRYPT 2005. EUROCRYPT 2005. Lecture Notes in Computer Science, vol 3494. Springer, Berlin, Heidelberg. https://doi.org/10.1007/11426639_27
 * 这个构造选自文章的第六节：Large Universe Construction
 *
 * 作者: mmsyan
 * 完成时间: 2024-12-18
 * 参考文献: Fuzzy Identity-Based Encryption
 */
public class FIBEb {
    private final int n; // 大宇宙方案中的n表示允许的最大的明文属性集合大小/用户属性集合大小。
    private final int d; // 加密方案的容错距离，控制解密时要求的最小匹配度
    private Pairing bp;
    private Element g; // g ∈ G1
    private Element y;
    private Element g1; // g1 = g^y
    private Element g2; // g2 ∈ G1
    private Element[] pk_Ti; // G1

    public FIBEb(int n, int d) {
        this.n = n;
        this.d = d;
        this.pk_Ti = new Element[n+2];
    }

    /**
     * 初始化方法，用于设置双线性对参数并生成主密钥和公钥
     * @param pairingFilePath 双线性对参数文件路径
     */
    public void setUp(String pairingFilePath) {
        bp = PairingFactory.getPairing(pairingFilePath);
        g = bp.getG1().newRandomElement().getImmutable();
        y = bp.getZr().newRandomElement().getImmutable();
        g1 = g.powZn(y).getImmutable();
        g2 = bp.getG1().newRandomElement().getImmutable();

        // 为每个属性生成主密钥和公钥。注意msk_ti[0]与pk_ti[0]是没有任何意义的。
        for (int i = 1; i < this.pk_Ti.length; i++) {
            pk_Ti[i] = bp.getG1().newRandomElement().getImmutable(); // pk: t_1 t_2 …… t_n, t_n+1 <- G1
        }
        System.out.println("已成功初始化，属性集合上限为 " + this.n + "，容错距离为 " + this.d);
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
        Element[] q = MathUtils.generateRandomPolynomial(d, y, bp);

        // 存储用户私钥的属性文件
        Properties skProperties = new Properties();

        // 为用户的每个属性生成对应的私钥
        for (int i : userAttributes) {
            Element ri = bp.getZr().newRandomElement().getImmutable(); // 获取随机的ri
            Element qi = MathUtils.qx(q, bp.getZr().newElement(i)); // 计算q(i)
            Element Di = (g2.powZn(qi)).mul(T(i).powZn(ri)).getImmutable(); // 计算Di = [g2^(q(i))] * [T(i)^ri]
            Element di = g.powZn(ri); // di = g^(ri)


            // 将私钥保存到属性文件中
            skProperties.setProperty("D" + i, ConversionUtils.bytes2String(Di.toBytes()));
            skProperties.setProperty("d" + i, ConversionUtils.bytes2String(di.toBytes()));
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

        // 计算加密后的密文组件 E' = M * e(g1, g2)^s
        Element EPrime = message.mul(bp.pairing(g1, g2).powZn(s)).getImmutable();
        ctProperties.setProperty("E' ", ConversionUtils.bytes2String(EPrime.toBytes()));

        // 计算加密后的密文组件 E'' = g^s
        Element EPrimePrime = g.powZn(s).getImmutable();
        ctProperties.setProperty("E'' ", ConversionUtils.bytes2String(EPrimePrime.toBytes()));


        // 为每个消息属性计算对应的密文组件Ei = T(i)^s
        for (int i : messageAttributes) {
            Element Ei = T(i).powZn(s).getImmutable();
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
        int[] S = MathUtils.findCommonAttributes(userAttributes, messageAttributes, this.d);
        if (S == null) {
            System.out.println("用户的属性与消息的属性匹配度不够，解密失败！");
            return null;
        }

        // 解密步骤
        Properties skProperties = PropertiesUtils.load(skFilePath);

        String EPrimeStr = ctProperties.getProperty("E' ");
        Element EPrime = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(EPrimeStr)).getImmutable();

        String EPrimePrimeStr = ctProperties.getProperty("E'' ");
        Element EPrimePrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(EPrimePrimeStr)).getImmutable();

        // 初始化分母元素为1
        Element denominator = bp.getGT().newOneElement().getImmutable();

        // 计算Lagrange基并累乘相应的e(Di, Ei)^delta项
        for (int i : S) {
            String DiStr = skProperties.getProperty("D" + i);
            Element Di = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DiStr)).getImmutable();
            String diStr = skProperties.getProperty("d" + i);
            Element di = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(diStr)).getImmutable();
            String EiStr = ctProperties.getProperty("E" + i);
            Element Ei = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(EiStr)).getImmutable();

            Element delta = MathUtils.computeLagrangeBasis(i, S, 0, bp);
            denominator = denominator.mul((bp.pairing(di, Ei).div(bp.pairing(Di, EPrimePrime))).powZn(delta)); // 计算分母项
        }

        // 最终解密得到的消息
        Element decryptedMessage = EPrime.mul(denominator);
        System.out.println("解密成功。解密得到的消息: " + decryptedMessage);
        return decryptedMessage;
    }

    private Element T(int x) {
        Element xElement = bp.getZr().newElement(x).getImmutable();
        Element xn = xElement.powZn(bp.getZr().newElement(n)).getImmutable();
        Element result = this.g2.powZn(xn).getImmutable(); // g2^(x^n)

        int[] N = new int[n+1];
        for (int i = 0; i < N.length; i++) {
            N[i] = i+1;
        }
        for (int i = 1; i <= n+1; i++) {
            Element ti = pk_Ti[i].duplicate().getImmutable();
            Element delta = MathUtils.computeLagrangeBasis(i, N, x, bp);
            result = result.mul(ti.powZn(delta));
        }

        return result;
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
            throw new IllegalArgumentException("属性集合不能无效或者是空集");
        if (attributes.length > n)
            throw new IllegalArgumentException("属性集合大小不能超过"+n);
    }
}
