package Accumulator;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Set;

public class Utils {
    /**
     * 展开多项式 ∏(x + xi)，其中 xi ∈ X
     *
     * 例如：
     * - 输入集合 {5}，计算 (x + 5) = x + 5，返回 [5, 1]
     * - 输入集合 {2, 3}，计算 (x + 2)(x + 3) = x² + 5x + 6，返回 [6, 5, 1]
     *
     * @param X 包含多项式中各项常数的集合
     * @param bp 配对对象，用于创建群元素
     * @return 多项式系数数组，其中 coeffs[i] 表示 x^i 的系数
     */
    public static Element[] expandPolynomial(Set<Element> X, Pairing bp) {
        int n = X.size();
        Element[] coeffs = new Element[n + 1];

        // 初始化系数数组为0
        for (int i = 0; i <= n; i++) {
            coeffs[i] = bp.getZr().newZeroElement();
        }

        // 将集合转换为数组便于处理
        Element[] elements = X.toArray(new Element[0]);

        // 初始状态：多项式为 1（即 x^0 的系数为 1）
        coeffs[0] = bp.getZr().newOneElement();

        // 逐个乘以 (x + xi)
        for (int i = 0; i < n; i++) {
            Element xi = elements[i];

            // 从高次项向低次项更新，避免覆盖问题
            for (int j = i + 1; j >= 1; j--) {
                // 乘以(x + xi)时：
                // 新的 x^j 系数 = 旧的 x^(j-1) 系数 * 1 + 旧的 x^j 系数 * xi
                // 但是这里我们要分两步：
                // 1. x项贡献：旧的 x^(j-1) 系数变成新的 x^j 系数
                // 2. xi项贡献：旧的 x^j 系数乘以xi
                Element oldCoeff = coeffs[j].duplicate();
                coeffs[j] = coeffs[j - 1].duplicate().add(oldCoeff.mul(xi));
            }

            // 常数项只受xi项影响：coeffs[0] = coeffs[0] * xi
            coeffs[0] = coeffs[0].mul(xi);
        }

        // 返回不可变的系数数组
        for (int i = 0; i <= n; i++) {
            coeffs[i] = coeffs[i].getImmutable();
        }

        return coeffs;
    }
}
