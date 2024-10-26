package Utils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * PropertiesUtils 类用于管理配置文件的加载和存储。
 * 提供从文件加载配置到 Properties 对象以及将 Properties 对象存储到文件的功能。
 */
public class PropertiesUtils {

    /**
     * 从指定的文件路径加载属性文件。
     *
     * @param filePath 属性文件的路径。
     * @return 包含文件中键值对的 Properties 对象。
     * @throws RuntimeException 如果加载文件时发生错误，将抛出运行时异常。
     */
    public static Properties load(String filePath) {
        Properties properties = new Properties();
        try (FileInputStream input = new FileInputStream(filePath)) {
            // 从输入流中加载属性
            properties.load(input);
        } catch (IOException ex) {
            // 简单打印错误信息到标准错误流
            System.err.println("加载属性文件时出错: " + filePath);
            ex.printStackTrace(System.err);  // 可选：打印堆栈跟踪
            throw new RuntimeException("加载属性文件时出错: " + filePath, ex);
        }
        return properties;
    }

    /**
     * 将 Properties 对象存储到指定的文件路径。
     *
     * @param properties 需要存储的 Properties 对象。
     * @param filePath 要存储到的文件路径。
     * @throws RuntimeException 如果存储文件时发生错误，将抛出运行时异常。
     */
    public static void store(Properties properties, String filePath) {
        try (FileOutputStream output = new FileOutputStream(filePath)) {
            // 将属性存储到输出流
            properties.store(output, filePath);
        } catch (IOException ex) {
            // 简单打印错误信息到标准错误流
            System.err.println("存储属性文件时出错: " + filePath);
            ex.printStackTrace(System.err);  // 可选：打印堆栈跟踪
            throw new RuntimeException("存储属性文件时出错: " + filePath, ex);
        }
    }
}
