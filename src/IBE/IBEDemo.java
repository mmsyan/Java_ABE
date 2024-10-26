package IBE;

import Utils.PropertiesUtils;
import Utils.MathUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Base64;
import java.util.Properties;

/**
 * 基于双线性对的身份加密(Identity-Based Encryption, IBE)演示类
 * 实现了IBE方案的设置、密钥生成、加密和解密过程
 */
public class IBEDemo {

    private Pairing pairing; // 配对参数对象
    private Element msk_x; // 主密钥

    /**
     * 初始化IBE方案
     * @param pairingFilePath 配对参数文件路径
     * @param pkFilePath 公钥文件路径
     */
    public void setUp(String pairingFilePath, String pkFilePath) {
        this.pairing = PairingFactory.getPairing(pairingFilePath); // 加载配对参数
        this.msk_x = pairing.getZr().newRandomElement().getImmutable(); // 生成随机主密钥

        Element g = pairing.getG1().newRandomElement().getImmutable(); // 生成随机生成元
        Element gx = g.powZn(msk_x); // 计算g^x
        Properties pkProperties = new Properties(); // 创建公钥属性
        pkProperties.setProperty("pk_g", Base64.getEncoder().encodeToString(g.toBytes())); // 编码g
        pkProperties.setProperty("pk_gx", Base64.getEncoder().encodeToString(gx.toBytes())); // 编码g^x
        PropertiesUtils.store(pkProperties, pkFilePath); // 存储公钥属性
    }

    /**
     * 生成用户密钥
     * @param id 用户身份标识
     * @param skFilePath 私钥文件路径
     */
    public void keyGeneration(String id, String skFilePath) {
        Element Qid = MathUtils.H1(id, pairing); // 计算Qid = H1(id)
        Element sk = Qid.powZn(msk_x); // 计算用户私钥 sk = Qid^x

        Properties skProperties = new Properties(); // 创建私钥属性
        skProperties.setProperty("sk", Base64.getEncoder().encodeToString(sk.toBytes())); // 编码私钥
        PropertiesUtils.store(skProperties, skFilePath); // 存储私钥属性
    }

    /**
     * 加密消息
     * @param id 用户身份标识
     * @param message 明文消息
     * @param pkFilePath 公钥文件路径
     * @param ctFilePath 密文文件路径
     */
    public void encrypt(String id, String message, String pkFilePath, String ctFilePath) {
        Element Qid = MathUtils.H1(id, pairing); // 计算Qid = H1(id)
        Element r = pairing.getZr().newRandomElement(); // 生成随机数r

        Properties pkProperties = PropertiesUtils.load(pkFilePath); // 加载公钥属性
        Element pk_g = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProperties.getProperty("pk_g"))).getImmutable(); // 解码g
        Element pk_gx = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(pkProperties.getProperty("pk_gx"))).getImmutable(); // 解码g^x

        Element Gid = pairing.pairing(Qid, pk_gx).powZn(r).getImmutable(); // 计算e(Qid, pk_gx)^r
        Element C1 = pk_g.powZn(r); // 计算C1 = g^r
        byte[] C2 = MathUtils.xor(message.getBytes(), MathUtils.H2(Gid)); // 计算C2 = M XOR H2(Gid)

        Properties ctProperties = new Properties(); // 创建密文属性
        ctProperties.setProperty("C1", Base64.getEncoder().encodeToString(C1.toBytes())); // 编码C1
        ctProperties.setProperty("C2", Base64.getEncoder().encodeToString(C2)); // 编码C2
        PropertiesUtils.store(ctProperties, ctFilePath); // 存储密文属性
    }

    /**
     * 解密密文
     * @param skFilePath 私钥文件路径
     * @param ctFilePath 密文文件路径
     * @return 解密后的明文消息
     */
    public String decrypt(String skFilePath, String ctFilePath) {
        Properties skProperties = PropertiesUtils.load(skFilePath); // 加载私钥属性
        Properties ctProperties = PropertiesUtils.load(ctFilePath); // 加载密文属性
        Element sk = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(skProperties.getProperty("sk"))).getImmutable(); // 解码私钥
        Element C1 = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(ctProperties.getProperty("C1"))).getImmutable(); // 解码C1
        Element Gid = pairing.pairing(sk, C1); // 计算e(sk, C1)
        String C2String = ctProperties.getProperty("C2"); // 获取C2
        byte[] C2 = Base64.getDecoder().decode(C2String); // 解码C2

        byte[] message_bytes = MathUtils.xor(C2, MathUtils.H2(Gid)); // 计算M = C2 XOR H2(Gid)
        return new String(message_bytes); // 返回解密后的明文消息
    }

    public static void main(String[] args) {
        String idAlice = "Alice@example.com";
        String idBob = "Bob@example.com";
        String message = "Identity Based Encryption Test";

        String pkFilePath = "src/IBE/IBEFile/pk.properties";
        String skAliceFilePath = "src/IBE/IBEFile/sk_Alice.properties";
        String skBobFilePath = "src/IBE/IBEFile/sk_Bob.properties";
        String ctFilePath = "src/IBE/IBEFile/ct.properties";

        IBEDemo ibeInstance = new IBEDemo();
        ibeInstance.setUp("a.properties", pkFilePath); // 初始化IBE方案
        ibeInstance.keyGeneration(idAlice, skAliceFilePath); // 生成Alice的密钥
        ibeInstance.keyGeneration(idBob, skBobFilePath); // 生成Bob的密钥

        // Alice加密消息并解密
        ibeInstance.encrypt(idAlice, message, pkFilePath, ctFilePath); // Alice加密消息
        String plainText1 = ibeInstance.decrypt(skAliceFilePath, ctFilePath); // Alice解密消息
        if (plainText1.equals(message)) {
            System.out.printf("解密成功! 明文消息是: %s \n", plainText1); // 打印解密成功信息
        }

        // Bob尝试解密Alice的消息
        ibeInstance.encrypt(idAlice, message, pkFilePath, ctFilePath); // Alice再次加密消息
        String plainText2 = ibeInstance.decrypt(skBobFilePath, ctFilePath); // Bob尝试解密
        if (!plainText2.equals(message)) {
            System.out.printf("解密失败! 错误的消息是: %s \n", plainText2); // 打印解密失败信息
        }
    }
}