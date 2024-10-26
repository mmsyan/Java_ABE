package Utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MathUtils {

    public static Element H1(String string, Pairing bp) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(string.getBytes());
            byte[] m = md.digest();
            return bp.getG1().newElementFromHash(m, 0, m.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] H2(Element e) {
        String eString = new String(e.toBytes());
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(eString.getBytes());
            return md.digest();
        } catch (NoSuchAlgorithmException err) {
            throw new RuntimeException(err);
        }
    }

    public static byte[] xor(byte[] b1, byte[] b2) {
        int minLength = Math.min(b1.length, b2.length);
        byte[] result = new byte[minLength];

        for (int i = 0; i < minLength; i++) {
            result[i] = (byte) (b1[i] ^ b2[i]);
        }
        return result;
    }

    // 生成一个degree-1次、常数项系数为constantTerm的多项式
    public static Element[] generateRandomPolynomial(int degree, Element constantTerm, Pairing pairing) {
        Element[] coefficients = new Element[degree];
        coefficients[0] = constantTerm;  // 常数项系数
        for (int i = 1; i < degree; i++) {
            coefficients[i] = pairing.getZr().newRandomElement().getImmutable();
        }
        return coefficients;
    }

    /**
     * 使用秦九韶算法在给定点处计算多项式的值。
     *
     * @param coefficients 多项式系数的数组，其中 coefficients[i] 对应于 x^i 的系数。
     * @param x 要计算多项式值的点。
     * @return 在给定点处的多项式计算结果。
     */
    public static Element qx(Element[] coefficients, Element x) {
        // 从最高次项系数作为初始结果开始
        Element result = coefficients[coefficients.length - 1].getImmutable();

        // 以相反顺序遍历剩余的系数
        for (int i = coefficients.length - 2; i >= 0; i--) {
            // 将当前结果乘以 x 并加上下一个系数
            result = result.mul(x).add(coefficients[i]);
        }

        // 返回计算结果
        return result;
    }

    public static int[] findCommonAttributes(int[] messageAttributes, int[] userAttributes, int requiredCount) {
        Set<Integer> messageAttributeSet = new HashSet<>();
        for (int attribute : messageAttributes) {
            messageAttributeSet.add(attribute);
        }
        List<Integer> commonAttributes = new ArrayList<>();
        for (int attribute : userAttributes) {
            if (messageAttributeSet.contains(attribute)) {
                commonAttributes.add(attribute);
            }
        }
        if (commonAttributes.size() >= requiredCount) {
            // Return the first requiredCount common attributes
            int[] subset = new int[requiredCount];
            for (int i = 0; i < requiredCount; i++) {
                subset[i] = commonAttributes.get(i);
            }
            return subset;
        } else {
            return null;
        }
    }

    /**
     * Computes the Lagrange basis polynomial at a given point x.
     *
     * @param i The element for which the Lagrange basis polynomial is being computed.
     * @param s An array of integers representing the x-coordinates of known data points.
     * @param x The point at which to evaluate the Lagrange basis polynomial.
     * @return The value of the Lagrange basis polynomial at the given point x.
     */
    public static Element computeLagrangeBasis(int i, int[] s, int x, Pairing bp) {
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        Element delta = bp.getZr().newOneElement().getImmutable();

        for (int j : s) {
            if (i != j) {
                Element numerator = xElement.sub(bp.getZr().newElement(j));
                Element denominator = iElement.sub(bp.getZr().newElement(j));
                delta = delta.mul(numerator.div(denominator));
            }
        }
        return delta;
    }
}
