package Utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class GaussElementUtils {
    /**
     * @param ElementLSSSMatrix   m行n列
     * @param constantVector   长度为n的向量
     * @return 求解一个长度为m的wVector。要求(1*m) wVector * (m*n) ElementLSSSMatrix = (1*n) constantVector
     * */
    public static Element[] computeMatrixEquation(Element[][] ElementLSSSMatrix, Element[] constantVector) {
        if (ElementLSSSMatrix.length == 0 || ElementLSSSMatrix[0].length == 0) {
            throw new IllegalArgumentException("Coefficient matrix M must not be empty.");
        }

        // constantVector 应该是长度为 n 的向量，而 ElementLSSSMatrix 是 m 行 n 列矩阵
        int m = ElementLSSSMatrix.length;   // 系数矩阵的行数
        int n = ElementLSSSMatrix[0].length; // 系数矩阵的列数
        if (constantVector.length != n) {
            throw new IllegalArgumentException(
                    "Length of constant vector (" + constantVector.length + ") must match the number of columns in M (" + n + ")."
            );
        }

        // 构建增广矩阵 (ElementLSSSMatrix^T) * wVector = constantVector
        Element[][] augmentedMatrix = new Element[n][m + 1]; // 增广矩阵，维度是 n 行 m + 1 列

        // 构建增广矩阵的左半部分是 ElementLSSSMatrix 的转置
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                augmentedMatrix[i][j] = ElementLSSSMatrix[j][i].duplicate(); // 交换行列
            }
            augmentedMatrix[i][m] = constantVector[i].duplicate();
        }

        // 进行高斯消元法
        int rank = 0; // 记录秩
        for (int k = 0; k < m; k++) {
            // 寻找非零主元
            int maxRow = rank;
            for (int i = rank + 1; i < n; i++) {
                if (!augmentedMatrix[i][k].isZero() && augmentedMatrix[maxRow][k].isZero()) {
                    maxRow = i;
                }
            }

            // 如果该列全为零，跳过
            if (augmentedMatrix[maxRow][k].isZero()) {
                continue;
            }

            // 交换行，将主元移到对角线位置
            if (maxRow != rank) {
                Element[] temp = augmentedMatrix[rank];
                augmentedMatrix[rank] = augmentedMatrix[maxRow];
                augmentedMatrix[maxRow] = temp;
            }

            // 消元
            for (int i = rank + 1; i < n; i++) {
                if (augmentedMatrix[i][k].isZero()) continue;
                Element factor = augmentedMatrix[i][k].duplicate().div(augmentedMatrix[rank][k]);
                for (int j = k; j <= m; j++) {
                    augmentedMatrix[i][j].sub(factor.duplicate().mul(augmentedMatrix[rank][j]));
                }
            }

            rank++;
        }

        // 检查无解情况
        for (int i = rank; i < n; i++) {
            if (!augmentedMatrix[i][m].isZero()) {
                return null; // 矛盾行，无解
            }
        }

        // 检查是否存在多解
        if (rank < m) {
            throw new IllegalStateException("The system has infinite solutions.");
        }

        // 回代求解
        Element[] wVector = new Element[m];
        for (int i = 0; i < m; i++) {
            wVector[i] = augmentedMatrix[0][0].getField().newZeroElement(); // 初始化解向量
        }

        // 从最后一行开始回代
        for (int i = rank - 1; i >= 0; i--) {
            Element sum = augmentedMatrix[0][0].getField().newZeroElement();
            for (int j = i + 1; j < m; j++) {
                sum.add(augmentedMatrix[i][j].duplicate().mul(wVector[j]));
            }
            wVector[i] = augmentedMatrix[i][m].duplicate().sub(sum).div(augmentedMatrix[i][i]);
        }

        return wVector;
    }

    public static void test1() {
        // 示例代码：调用computeMatrixEquation
        // 创建Element矩阵和常量向量后测试即可
        Pairing bp = PairingFactory.getPairing("a.properties");
        //              【0  1   1】
        // 【x1 x2 x3】  【2  4  -2】  = 【2*(x2), (x1)+4*(x2)+3*(x3), (x1)-2*(x2)+15*(x3)】
        //              【0  3  15】
        Element[][] M = new Element[][]{
                {bp.getZr().newElement(0).getImmutable(),bp.getZr().newElement(1).getImmutable(),bp.getZr().newElement(1).getImmutable()},
                {bp.getZr().newElement(2).getImmutable(),bp.getZr().newElement(4).getImmutable(),bp.getZr().newElement(-2).getImmutable()},
                {bp.getZr().newElement(0).getImmutable(),bp.getZr().newElement(3).getImmutable(),bp.getZr().newElement(15).getImmutable()},
        };
        Element[] B = new Element[] {bp.getZr().newElement(2).getImmutable(),bp.getZr().newElement(18).getImmutable(),bp.getZr().newElement(42).getImmutable()};
        // 调用求解函数计算 wVector
        Element[] wVector = computeMatrixEquation(M, B);

        // 确保求解结果不为 null
        assert wVector != null;

        // 输出解向量 wVector
        System.out.println("wVector:");
        for (Element r : wVector) {
            System.out.print(r + "  ");
        }
        System.out.println();

        // 验证 wVector * M = B
        System.out.println("Verifying wVector * M = B...");
        for (int i = 0; i < M.length; i++) {
            Element calculated = bp.getZr().newZeroElement(); // 初始化一个零元素

            // 计算 wVector[i] * M[i][j] 并累加
            for (int j = 0; j < M[0].length; j++) {
                Element product = wVector[j].duplicate().mul(M[i][j]);
                calculated.add(product);
            }

            // 对比计算结果与常量向量 B 中的对应元素
            if (!calculated.isEqual(B[i])) {
                System.out.println("Verification failed at row " + i + ": expected " + B[i] + ", but got " + calculated);
            } else {
                System.out.println("Row " + i + " verification passed.");
            }
        }
    }

    public static void main(String[] args) {
        test1();
    }
}
