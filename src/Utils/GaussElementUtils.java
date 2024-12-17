package Utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class GaussElementUtils {
    /**
     * 列主元高斯消去法解线性方程组
     * @param M 系数矩阵，m行n列
     * @param B 常数矩阵，长度为m
     * @return 方程组的解，如果有多组解则返回任意一组，如果没有解则返回null
     */
    public static Element[] computeMatrixEquation(Element[][] M, Element[] B) {
        if (M.length == 0 || M[0].length == 0) {
            throw new IllegalArgumentException("Coefficient matrix M must not be empty.");
        }
        if (B.length != M.length) {
            throw new IllegalArgumentException(
                    "Length of constant matrix B (" + B.length + ") must match the number of rows in M (" + M.length + ")."
            );
        }

        int m = M.length; // 系数矩阵的行数
        int n = M[0].length; // 系数矩阵的列数
        Element[][] augmentedMatrix = new Element[m][n + 1]; // 增广矩阵

        // 构建增广矩阵
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < n; j++) {
                augmentedMatrix[i][j] = M[i][j].duplicate();
            }
            augmentedMatrix[i][n] = B[i].duplicate();
        }

        // 进行高斯消元
        int rank = 0; // 记录秩
        for (int k = 0; k < n; k++) {
            // 寻找非零的主元
            int maxRow = rank;
            for (int i = rank + 1; i < m; i++) {
                if (!augmentedMatrix[i][k].isZero() && augmentedMatrix[maxRow][k].isZero()) {
                    maxRow = i;
                }
            }

            // 如果该列全为0，跳过
            if (augmentedMatrix[maxRow][k].isZero()) {
                continue;
            }

            // 交换行，将主元移到对角线位置
            Element[] temp = augmentedMatrix[rank];
            augmentedMatrix[rank] = augmentedMatrix[maxRow];
            augmentedMatrix[maxRow] = temp;

            // 消元
            for (int i = rank + 1; i < m; i++) {
                if (augmentedMatrix[i][k].isZero()) continue;
                Element factor = augmentedMatrix[i][k].duplicate().div(augmentedMatrix[rank][k]);
                for (int j = k; j <= n; j++) {
                    augmentedMatrix[i][j].sub(factor.duplicate().mul(augmentedMatrix[rank][j]));
                }
            }

            rank++;
        }

        // 检查无解情况
        for (int i = rank; i < m; i++) {
            if (!augmentedMatrix[i][n].isZero()) {
                return null; // 矛盾行，无解
            }
        }

        // 检查是否存在多解
        if (rank < n) {
            throw new IllegalStateException("The system has infinite solutions.");
        }

        // 回代求解
        Element[] x = new Element[n];
        for (int i = 0; i < n; i++) {
            x[i] = M[0][0].getField().newZeroElement(); // 初始化解向量
        }
        for (int i = rank - 1; i >= 0; i--) {
            Element sum = M[0][0].getField().newZeroElement();
            for (int j = i + 1; j < n; j++) {
                sum.add(augmentedMatrix[i][j].duplicate().mul(x[j]));
            }
            x[i] = augmentedMatrix[i][n].duplicate().sub(sum).div(augmentedMatrix[i][i]);
        }

        return x;
    }

    public static void test1() {
        // 示例代码：调用computeMatrixEquation
        // 创建Element矩阵和常量向量后测试即可
        Pairing bp = PairingFactory.getPairing("a.properties");
        Element[][] M = new Element[][]{
                {bp.getZr().newElement(0),bp.getZr().newElement(1),bp.getZr().newElement(1)},
                {bp.getZr().newElement(2),bp.getZr().newElement(4),bp.getZr().newElement(-2)},
                {bp.getZr().newElement(0),bp.getZr().newElement(3),bp.getZr().newElement(15)},
        };
        Element[] B = new Element[] {bp.getZr().newElement(4),bp.getZr().newElement(2),bp.getZr().newElement(36)};
        Element[] result = computeMatrixEquation(M, B);
        System.out.println(result[0]+" "+result[1]+" "+result[2]);
    }

    public static void test2() {
        // 示例代码：调用computeMatrixEquation
        // 创建Element矩阵和常量向量后测试即可
        Pairing bp = PairingFactory.getPairing("a.properties");
        Element[][] M = new Element[][]{
                {bp.getZr().newElement(2),bp.getZr().newElement(1)},
                {bp.getZr().newElement(-3),bp.getZr().newElement(-1)},
                {bp.getZr().newElement(1),bp.getZr().newElement(1)},
        };
        Element[] B = new Element[] {bp.getZr().newElement(1),bp.getZr().newElement(-2),bp.getZr().newElement(0)};
        Element[] result = computeMatrixEquation(M, B);
        for (Element r : result) {
            System.out.println(r);
        }
    }

    public static void test3() {
        // 示例代码：调用computeMatrixEquation
        // 创建Element矩阵和常量向量后测试即可
        Pairing bp = PairingFactory.getPairing("a.properties");
        Element[][] M = new Element[][]{
                {bp.getZr().newElement(0), bp.getZr().newElement(0),bp.getZr().newElement(0),bp.getZr().newElement(-1),bp.getZr().newElement(0)}
        };
        Element[] B = new Element[] {bp.getZr().newElement(1)};
        Element[] result = computeMatrixEquation(M, B);
        for (Element r : result) {
            System.out.println(r);
        }
    }

    public static void main(String[] args) {
        test3();
    }
}