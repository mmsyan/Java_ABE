package Utils;

import java.util.Base64;

public class ConversionUtils {
    /**
     * 将 int 数组转换为字符串。
     *
     * @param intArray int 数组
     * @return 转换后的字符串
     */
    public static String intArray2String(int[] intArray) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < intArray.length; i++) {
            sb.append(intArray[i]);
            if (i < intArray.length - 1) {
                sb.append(", ");  // 可以根据需要更改分隔符
            }
        }
        return sb.toString();
    }

    /**
     * 将字符串转换为 int 数组。
     *
     * @param str 待转换的字符串，其中元素以指定分隔符分隔
     * @return 转换后的 int 数组
     */
    public static int[] String2intArray(String str) {
        String[] strArray = str.split(", ");  // 根据实际分隔符调整
        int[] intArray = new int[strArray.length];
        for (int i = 0; i < strArray.length; i++) {
            intArray[i] = Integer.parseInt(strArray[i]);
        }
        return intArray;
    }

    public static String bytes2String(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] String2Bytes(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }
}
