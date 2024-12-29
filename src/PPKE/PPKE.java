package PPKE;

import KPABE.AccessTreeKPABE;
import Utils.ConversionUtils;
import Utils.MathUtils;
import Utils.PropertiesUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.List;
import java.util.Properties;

/**
 * PE (Puncturable Encryption) 演示类
 * 该类展示了PE方案的初始化、密钥生成、加密、穿刺和解密过程。
 * M. D. Green and I. Miers, "Forward Secure Asynchronous Messaging from Puncturable Encryption,"
 * 2015 IEEE Symposium on Security and Privacy, San Jose, CA, USA, 2015, pp. 305-320, doi: 10.1109/SP.2015.26.
 * keywords: {Encryption;Public key;Proposals;Games;Electronic mail},
 * 这个构造选自文章的第IV节：Construction的A部分：A CPA-secure construction(Fig2)
 *
 * 作者: mmsyan
 * 完成时间: //
 * 参考文献: Forward Secure Asynchronous Messaging from Puncturable Encryption
 */
public class PPKE {
    private Pairing bp;
    private Element g;
    private Element alpha;
    private Element beta;
    private Element g1;
    private Element g2;

    private int d;
    private Element[] gQi;
    private Element[] q;


    public PPKE(int d) {
        this.d = d;
        this.gQi = new Element[d+1];
    }

    /**
     * 初始化方法，用于设置双线性对参数并生成主密钥和公钥
     * @param pairingFilePath 双线性对参数文件路径
     */
    public void setUp(String pairingFilePath) {
        bp = PairingFactory.getPairing(pairingFilePath);
        g = bp.getG1().newRandomElement().getImmutable();
        alpha = bp.getZr().newRandomElement().getImmutable();
        beta = bp.getZr().newRandomElement().getImmutable();
        g1 = g.powZn(alpha).getImmutable();
        g2 = g.powZn(beta).getImmutable();
    }

    private Element V(Element x) {
        return g.powZn(MathUtils.qx(q, x)).getImmutable();
    }

    /**
     * 密钥生成方法，根据用户的属性访问控制树生成密钥。
     * @param skFilePath 密钥存储文件路径
     */
    public void keyGeneration(String skFilePath, String tag0) {
        // 访问控制树操作：设置根节点的秘密值/多项式的常量/多项式在x=0处的取值
        Element r = bp.getZr().newRandomElement().getImmutable();
        this.q = MathUtils.generateRandomPolynomial(this.d+1, beta, bp);

        for (int i = 1; i <= d; i++) {
            gQi[i] = g.powZn(MathUtils.qx(q, bp.getZr().newElement(i))).getImmutable();
        }

        Element sk1 = g2.powZn(alpha.add(r)).getImmutable();
        Element sk2 = (V(MathUtils.H(tag0, bp))).powZn(r).getImmutable();
        Element sk3 = g.powZn(r).getImmutable();


        // 存储对应私钥
        Properties skProperties = new Properties();
        skProperties.setProperty("sk1", ConversionUtils.bytes2String(sk1.toBytes()));
        skProperties.setProperty("sk2", ConversionUtils.bytes2String(sk2.toBytes()));
        skProperties.setProperty("sk3", ConversionUtils.bytes2String(sk3.toBytes()));
        skProperties.setProperty("sk4", tag0);

        PropertiesUtils.store(skProperties, skFilePath);
    }

    /**
     * 加密方法，根据一组属性加密消息
     * @param message 要加密的消息
     * @param ctFilePath 加密文本存储文件路径
     */
    public void encrypt(Element message, List<String> tags, String ctFilePath) {
        Properties ctProperties = new Properties();

        Element s = bp.getZr().newRandomElement().getImmutable();
        Element ct1 = message.mul(bp.pairing(g1, g2).powZn(s)).getImmutable();  // M * e(g1, g2)^s
        ctProperties.setProperty("ct1", ConversionUtils.bytes2String(ct1.toBytes()));
        Element ct2 = g.powZn(s).getImmutable();
        ctProperties.setProperty("ct2", ConversionUtils.bytes2String(ct2.toBytes()));

        // 生成密文ct(3,d) = V(H(td))^s
        for (int i = 0; i < d; i++) {
            Element ct3 = V(MathUtils.H(tags.get(i), bp)).powZn(s);
            ctProperties.setProperty("ct(3, "+(i+1)+")", ConversionUtils.bytes2String(ct3.toBytes()));
        }
        PropertiesUtils.store(ctProperties, ctFilePath);
    }

    public void puncture(String sk1FilePath, String sk2FilePath, String tag) {
        
    }
}
