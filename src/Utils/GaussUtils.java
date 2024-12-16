package Utils;

public class GaussUtils {
    /**
     * 列主元高斯消去法解线性方程组
     * @param M 系数矩阵，m行n列
     * @param B 常数矩阵，长度为m
     * @return 方程组的解，如果有多组解则返回任意一组，如果没有解则返回null
     */
    public static double[] computeMatrixEquation(int[][] M, int[] B) {
        if (M.length == 0 || M[0].length == 0 || B.length != M.length) {
            throw new IllegalArgumentException("Invalid input matrices");
        }

        int m = M.length; // 系数矩阵的行数
        int n = M[0].length; // 系数矩阵的列数
        double[][] augmentedMatrix = new double[m][n + 1]; // 增广矩阵

        // 构建增广矩阵
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < n; j++) {
                augmentedMatrix[i][j] = M[i][j];
            }
            augmentedMatrix[i][n] = B[i];
        }

        // 进行高斯消元
        int rank = 0; // 记录秩
        for (int k = 0; k < n; k++) {
            // 寻找最大的主元
            int maxRow = rank;
            for (int i = rank + 1; i < m; i++) {
                if (Math.abs(augmentedMatrix[i][k]) > Math.abs(augmentedMatrix[maxRow][k])) {
                    maxRow = i;
                }
            }

            // 如果该列全为0，跳过
            if (Math.abs(augmentedMatrix[maxRow][k]) < 1e-9) {
                continue;
            }

            // 交换行，将最大主元移到对角线位置
            double[] temp = augmentedMatrix[rank];
            augmentedMatrix[rank] = augmentedMatrix[maxRow];
            augmentedMatrix[maxRow] = temp;

            // 消元
            for (int i = rank + 1; i < m; i++) {
                double factor = augmentedMatrix[i][k] / augmentedMatrix[rank][k];
                for (int j = k; j <= n; j++) {
                    augmentedMatrix[i][j] -= factor * augmentedMatrix[rank][j];
                }
            }

            rank++;
        }

        // 检查无解情况
        for (int i = rank; i < m; i++) {
            if (Math.abs(augmentedMatrix[i][n]) > 1e-9) {
                return null; // 矛盾行，无解
            }
        }

        // 检查是否存在多解
        if (rank < n) {
            throw new IllegalStateException("The system has infinite solutions.");
        }

        // 回代求解
        double[] x = new double[n];
        for (int i = rank - 1; i >= 0; i--) {
            double sum = 0;
            for (int j = i + 1; j < n; j++) {
                sum += augmentedMatrix[i][j] * x[j];
            }
            x[i] = (augmentedMatrix[i][n] - sum) / augmentedMatrix[i][i];
        }

        return x;
    }

    public static void main(String[] args) {
        int[][] M = {
                {2, 1},
                {-3, -1},
                {1, 1}
        };
        int[] B = {1, -2, 0};

        double[] solution = computeMatrixEquation(M, B);
        if (solution != null) {
            System.out.println("--------------方程组的根为---------------");
            for (int i = 0; i < solution.length; i++) {
                System.out.println("x" + (i + 1) + " = " + solution[i]);
            }
        } else {
            System.out.println("--------------方程组无解---------------");
        }
    }
}