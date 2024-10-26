package IBE;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Base64;
import java.util.Properties;

public class PropertiesDemo {

    // 打印 Element g 及其字节数组的十六进制形式
    public static void g2BytesPrint() {
        // 加载双线性对的参数
        Pairing bp = PairingFactory.getPairing("a.properties");

        // 生成 G1 群中的随机元素 g 并将其设置为不可变
        Element g = bp.getG1().newRandomElement().getImmutable();

        // 使用 %s 格式化输出 Element g
        System.out.printf("Element g is: %s%n", g);

        // 将 Element g 转换为字节数组并以十六进制格式输出
        byte[] g_to_bytes = g.toBytes();
        StringBuilder sb = new StringBuilder();
        for (byte b : g_to_bytes) {
            sb.append(String.format("%02X ", b));  // %02X 以两位十六进制格式输出
        }

        // 输出字节数组的十六进制表示
        System.out.printf("g.toBytes() is: %s%n", sb);

        Element g_recover = bp.getG1().newElementFromBytes(g_to_bytes);
        System.out.printf("Element g_recover is: %s%n", g);
    }

    // 演示使用 Properties 存储和读取元素的字节数组
    public static void propertiesPrint() {
        Pairing bp = PairingFactory.getPairing("a.properties");
        Element g = bp.getG1().newRandomElement().getImmutable();
        // 使用 %s 格式化输出 Element g
        System.out.printf("Element g is: %s%n", g);

        // 创建 Properties 对象，并将 g 的字节数组 Base64 编码后存储到 Properties 中
        Properties prop = new Properties();
        String g_key = "g";
        String g_value = Base64.getEncoder().encodeToString(g.toBytes());
        prop.setProperty(g_key, g_value);

        // 从 Properties 中读取 Base64 编码的 g 值，并将其解码为字节数组恢复成 Element g
        String g_value_recover = prop.getProperty("g");
        Element g_recover = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_value_recover)).getImmutable();

        // 打印恢复的 g 值
        System.out.printf("Recovered g is: %s%n", g_recover);
    }

    // 主函数
    public static void main(String[] args) {
        // 调用 g2BytesPrint 方法
        g2BytesPrint();

        // 调用 propertiesPrint 方法
        propertiesPrint();
    }
}
