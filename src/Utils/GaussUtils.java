package Utils;

public class GaussUtils {
    /**
     * 列主元高斯消去法解线性方程组
     * @param M 系数矩阵，m行n列
     * @param B 常数矩阵，长度为m
     * @return 方程组的解，如果有多组解则返回任意一组，如果没有解则返回null
     */
    public static double[] computeMatrixEquation(int[][] M, int[] B) {
        int m = M.length;
        int n = M[0].length;

        if (B.length != m) {
            throw new IllegalArgumentException("The length of B must match the number of rows in M.");
        }

        // Create an augmented matrix
        double[][] augmentedMatrix = new double[m][n + 1];
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < n; j++) {
                augmentedMatrix[i][j] = M[i][j];
            }
            augmentedMatrix[i][n] = B[i];
        }

        // Perform Gaussian elimination
        for (int col = 0; col < Math.min(m, n); col++) {
            // Find the pivot row
            int pivotRow = col;
            for (int row = col + 1; row < m; row++) {
                if (Math.abs(augmentedMatrix[row][col]) > Math.abs(augmentedMatrix[pivotRow][col])) {
                    pivotRow = row;
                }
            }

            // Swap the current row with the pivot row
            double[] temp = augmentedMatrix[col];
            augmentedMatrix[col] = augmentedMatrix[pivotRow];
            augmentedMatrix[pivotRow] = temp;

            // Check if the pivot is zero (no unique solution)
            if (Math.abs(augmentedMatrix[col][col]) < 1e-9) {
                continue;
            }

            // Normalize the pivot row
            double pivot = augmentedMatrix[col][col];
            for (int j = col; j < n + 1; j++) {
                augmentedMatrix[col][j] /= pivot;
            }

            // Eliminate the current column in all rows below the pivot
            for (int row = col + 1; row < m; row++) {
                double factor = augmentedMatrix[row][col];
                for (int j = col; j < n + 1; j++) {
                    augmentedMatrix[row][j] -= factor * augmentedMatrix[col][j];
                }
            }
        }

        // Back substitution
        double[] solution = new double[n];
        boolean[] freeVariables = new boolean[n];
        for (int i = n - 1; i >= 0; i--) {
            if (i >= m || Math.abs(augmentedMatrix[i][i]) < 1e-9) {
                freeVariables[i] = true;
                continue;
            }
            solution[i] = augmentedMatrix[i][n];
            for (int j = i + 1; j < n; j++) {
                solution[i] -= augmentedMatrix[i][j] * solution[j];
            }
        }

        // Check for consistency
        for (int i = m - 1; i >= 0; i--) {
            double sum = 0;
            for (int j = 0; j < n; j++) {
                sum += augmentedMatrix[i][j] * solution[j];
            }
            if (Math.abs(sum - augmentedMatrix[i][n]) > 1e-9) {
                return null; // No solution
            }
        }

        // Handle free variables (if any)
        for (int i = 0; i < n; i++) {
            if (freeVariables[i]) {
                solution[i] = 0; // Arbitrarily set free variables to 0
            }
        }

        return solution;
    }


    public static void test1() {
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

    public static void test2() {
        int[][] M = {
                {0, 0, 0, -1, 0},
        };
        int[] B = {1};

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

    public static void main(String[] args) {
        test2();
    }
}