package Utils;

import org.apache.commons.math4.legacy.linear.Array2DRowRealMatrix;
import org.apache.commons.math4.legacy.linear.LUDecomposition;
import org.apache.commons.math4.legacy.linear.RealMatrix;

/**
 * 矩阵工具类，提供矩阵是否可逆的判断以及求逆矩阵的功能。
 */
public class MatrixUtils {

    /**
     * 判断给定的整数矩阵是否可逆。
     *
     * @param m 整数矩阵
     * @return 如果矩阵可逆返回true，否则返回false。
     */
    public static boolean isInvertible(int[][] m) {
        // 将int[][]矩阵转换为RealMatrix
        double[][] doubleArray = new double[m.length][m[0].length];

        // 遍历intArray并转换每个元素到doubleArray
        for (int i = 0; i < m.length; i++) {
            for (int j = 0; j < m[i].length; j++) {
                doubleArray[i][j] = (double) m[i][j];
            }
        }
        RealMatrix realMatrix = new Array2DRowRealMatrix(doubleArray);

        // 使用LU分解来检查矩阵是否可逆
        LUDecomposition lu = new LUDecomposition(realMatrix);

        // 如果矩阵不可逆，会抛出SingularMatrixException异常
        try {
            lu.getSolver().getInverse();
            return true; // 矩阵是可逆的
        } catch (Exception e) {
            return false; // 矩阵不可逆
        }
    }

    /**
     * 若矩阵m可逆，返回其逆矩阵；否则，返回null。
     *
     * @param m 整数矩阵
     * @return 逆矩阵或null
     */
    public static double[][] getInverse(int[][] m) {
        // 将int[][]矩阵转换为RealMatrix
        double[][] doubleArray = new double[m.length][m[0].length];
        for (int i = 0; i < m.length; i++) {
            for (int j = 0; j < m[i].length; j++) {
                doubleArray[i][j] = (double) m[i][j];
            }
        }
        RealMatrix realMatrix = new Array2DRowRealMatrix(doubleArray);

        // 使用LU分解来检查矩阵是否可逆
        LUDecomposition lu = new LUDecomposition(realMatrix);

        // 如果矩阵不可逆，会抛出SingularMatrixException异常
        try {
            RealMatrix inverse = lu.getSolver().getInverse();
            // 将RealMatrix转换为double[][]并返回
            return inverse.getData();
        } catch (Exception e) {
            return null; // 矩阵不可逆
        }
    }

    /**
     * 测试矩阵是否可逆。
     */
    public static void testIsInvertible() {
        // 定义一系列可逆和不可逆的矩阵
        int[][] invertible1 = new int[][]{{1, 2}, {3, 4}};
        int[][] invertible2 = new int[][]{{1, 2, 3}, {0, 1, 4}, {5, 6, 0}};
        int[][] invertible3 = new int[][]{
                {9, 3, 0, 9},
                {-5, -2, 6, -2},
                {-5, 3, 6, 3},
                {-6, 3, 0, 3}
        };
        int[][] invertible4 = new int[][]{
                {1, 1, 0, 0, 0},
                {0, 1, 0, 0, 0},
                {0, 0, 1, 0, 0},
                {0, 0, 0, 1, 0},
                {0, 0, 0, 0, 1}
        };
        int[][] nonInvertible1 = new int[][]{{1, 2}, {2, 4}};
        int[][] nonInvertible2 = new int[][]{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
        int[][] nonInvertible3 = new int[][]{
                {1, 1, 1, 1},
                {2, 2, 2, 2},
                {3, 3, 3, 3},
                {4, 4, 4, 4}
        };
        // 打印每个矩阵是否可逆的结果
        System.out.println(isInvertible(invertible1));
        System.out.println(isInvertible(invertible2));
        System.out.println(isInvertible(invertible3));
        System.out.println(isInvertible(invertible4));
        System.out.println(isInvertible(nonInvertible1));
        System.out.println(isInvertible(nonInvertible2));
        System.out.println(isInvertible(nonInvertible3));
    }

    /**
     * 打印二维矩阵。
     *
     * @param matrix 要打印的二维矩阵
     */
    public static void printMatrix(int[][] matrix) {
        if (matrix == null) {
            System.out.println("Matrix is null");
            return;
        }
        for (int[] row : matrix) {
            for (int value : row) {
                System.out.printf("%d ", value); // 打印每个元素，保留4位小数，左对齐，总宽度为10
            }
            System.out.println(); // 每打印完一行后换行
        }
        System.out.println();
    }

    /**
     * 打印二维矩阵。
     *
     * @param matrix 要打印的二维矩阵
     */
    public static void printMatrix(double[][] matrix) {
        if (matrix == null) {
            System.out.println("Matrix is null");
            return;
        }
        for (double[] row : matrix) {
            for (double value : row) {
                System.out.printf("%-10.4f ", value); // 打印每个元素，保留4位小数，左对齐，总宽度为10
            }
            System.out.println(); // 每打印完一行后换行
        }
        System.out.println();
    }

    /**
     * 测试获取矩阵的逆。
     */
    public static void testGetInvertible() {
        // 定义一系列可逆和不可逆的矩阵
        int[][] invertible1 = new int[][]{{1, 2}, {3, 4}};
        int[][] invertible2 = new int[][]{{1, 2, 3}, {0, 1, 4}, {5, 6, 0}};
        int[][] invertible3 = new int[][]{
                {9, 3, 0, 9},
                {-5, -2, 6, -2},
                {-5, 3, 6, 3},
                {-6, 3, 0, 3}
        };
        int[][] invertible4 = new int[][]{
                {1, 1, 0, 0, 0},
                {0, 1, 0, 0, 0},
                {0, 0, 1, 0, 0},
                {0, 0, 0, 1, 0},
                {0, 0, 0, 0, 1}
        };
        int[][] nonInvertible1 = new int[][]{{1, 2}, {2, 4}};
        int[][] nonInvertible2 = new int[][]{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
        int[][] nonInvertible3 = new int[][]{
                {1, 1, 1, 1},
                {2, 2, 2, 2},
                {3, 3, 3, 3},
                {4, 4, 4, 4}
        };
        // 打印每个矩阵的逆
        printMatrix(getInverse(invertible1));
        printMatrix(getInverse(invertible2));
        printMatrix(getInverse(invertible3));
        printMatrix(getInverse(invertible4));
        printMatrix(getInverse(nonInvertible1));
        printMatrix(getInverse(nonInvertible2));
        printMatrix(getInverse(nonInvertible3));
    }

    /**
     * 程序入口点。
     *
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        testGetInvertible();
    }
}