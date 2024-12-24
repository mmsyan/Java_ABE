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
 * 这个构造选自文章的第5节：Large Universe Construction
 *
 * 作者: mmsyan
 * 完成时间: 2024-12-24
 * 参考文献: Attribute-based encryption for fine-grained access control of encrypted data
 */
public class KPABEb {
    private int n; // 大宇宙方案中的n表示允许的最大的明文属性集合大小 | 用户属性集合大小。
    private Pairing bp; // 基于双线性对的密码学对象
    private Element g; // G1群的生成元
    private Element msk_y; // 主密钥y: Zr群的密钥元素
    private Element g1;  // g1 = g^y
    private Element g2;  // g2 ∈ G1
    private Element[] pk_ti; // 公共参数ti: G1群的密钥元素数组


    /**
     * 构造函数，用于初始化KPABEb类
     * @param n 大宇宙方案中的n表示允许的最大的明文属性集合大小 | 用户属性集合大小。
     */
    public KPABEb(int n) {
        this.n = n;
        this.pk_ti = new Element[n+2];
    }

    /**
     * 初始化方法，用于设置双线性对参数并生成主密钥和公钥
     * KPABEa的set up和FIBEa的set up 如出一辙
     * @param pairingFilePath 双线性对参数文件路径
     */
    public void setUp(String pairingFilePath) {
        bp = PairingFactory.getPairing(pairingFilePath);
        g = bp.getG1().newRandomElement().getImmutable();
        msk_y = bp.getZr().newRandomElement().getImmutable();
        g1 = g.powZn(msk_y).getImmutable();  // g1 = g^y
        g2 = bp.getG1().newRandomElement().getImmutable(); // g2 is random element of G1

        // 为每个属性生成公钥。注意pk_ti[0]是没有任何意义的。
        for (int i = 1; i < pk_ti.length; i++) {
            pk_ti[i] = bp.getG1().newRandomElement().getImmutable(); // msk: t1 t2 …… tn tn+1 <- G1
        }
        msk_y = bp.getZr().newRandomElement().getImmutable(); // msk: y <- Zr
        System.out.println("已成功初始化，属性集合的大小上限为 " + this.n);
    }

    /**
     * 加密方法，根据一组属性加密消息
     * @param messageAttributes 加密消息的属性数组
     * @param message 要加密的消息，是GT当中的元素
     * @param ctFilePath 加密文本存储文件路径
     */
    public void encrypt(int[] messageAttributes, Element message, String ctFilePath) {
        checkAttributeSet(messageAttributes);

        Properties ctProperties = new Properties();
        ctProperties.setProperty("Message Attributes w' ", ConversionUtils.intArray2String(messageAttributes));

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

        // 为用户访问控制树的每个叶子节点x生成对应的Dx和Rx(不是跟着属性i走！)
        for (AccessTreeKPABE.Node n : userAttributes) {
            if (n.isLeave()) {
                Element rx = bp.getZr().newRandomElement().getImmutable();
                Element qx0 = MathUtils.qx(n.polynomial, bp.getZr().newZeroElement()
                );

                // for each leaf node x: Dx = (g2^(qx0))*(T(i)^rx) where i = attr(x)
                Element Dx = (g2.powZn(qx0)).mul(T(n.attribute).powZn(rx));
                skProperties.setProperty("Dx" + n.leafID, ConversionUtils.bytes2String(Dx.toBytes()));

                // for each leaf node x: Rx = g^rx
                Element Rx = g.powZn(rx);
                skProperties.setProperty("Rx" + n.leafID, ConversionUtils.bytes2String(Rx.toBytes()));
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

        // 解密需要准备好E'和E''
        Properties skProperties = PropertiesUtils.load(skFilePath);
        String EPrimeStr = ctProperties.getProperty("E' ");
        Element EPrime = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(EPrimeStr)).getImmutable();
        String EPrimePrimeStr = ctProperties.getProperty("E'' ");
        Element EPrimePrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(EPrimePrimeStr)).getImmutable();

        // 解密需要准备好Ei，这与属性对应。还需要准备好Dx和Rx，这与叶子节点对应。
        HashMap<Integer, Element> ciphertextEi = new HashMap<>();
        HashMap<Integer, Element> secretKeyDx = new HashMap<>();
        HashMap<Integer, Element> secretKeyRx = new HashMap<>();
        for (int i : messageAttributes) {
            String EiStr = ctProperties.getProperty("E" + i);
            Element Ei = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(EiStr)).getImmutable();
            ciphertextEi.put(i, Ei);
        }

        for (AccessTreeKPABE.Node n : userAttributes) {
            if (n.isLeave()) {
                String DxStr = skProperties.getProperty("Dx" + n.leafID);
                Element Dx = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DxStr)).getImmutable();
                secretKeyDx.put(n.leafID, Dx);

                String RxStr = skProperties.getProperty("Rx" + n.leafID);
                Element Rx = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(RxStr)).getImmutable();
                secretKeyRx.put(n.leafID, Rx);
            }
        }

        // 调用decryptNode(E, D, root)得到Y^s
        Element Ys = userAttributes.decryptNodeB(messageAttributes, secretKeyDx, secretKeyRx, ciphertextEi, EPrimePrime, bp);
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

    private Element T(int x) {
        Element xElement = bp.getZr().newElement(x).getImmutable();
        Element xn = xElement.powZn(bp.getZr().newElement(n)).getImmutable();
        Element result = this.g2.powZn(xn).getImmutable(); // g2^(x^n)

        int[] N = new int[n+1];
        for (int i = 0; i < N.length; i++) {
            N[i] = i+1;
        }
        for (int i = 1; i <= n+1; i++) {
            Element ti = pk_ti[i].duplicate().getImmutable();
            Element delta = MathUtils.computeLagrangeBasis(i, N, x, bp);
            result = result.mul(ti.powZn(delta));
        }

        return result;
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
            if (a > this.n) throw new IllegalArgumentException("属性元素不能超过属性宇宙的范围");
        }
    }

}
