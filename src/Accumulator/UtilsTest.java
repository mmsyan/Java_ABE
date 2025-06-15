package Accumulator;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class UtilsTest {
    public static Pairing bp = PairingFactory.getPairing("a.properties");
    public static void main(String[] args) {
        System.out.println("=== 多项式展开函数测试 ===");

        // 测试1: 空集合
        testEmptySet();

        // 测试2: 单元素集合
        testSingleElement();

        // 测试3: 两元素集合
        testTwoElements();

        // 测试4: 三元素集合
        testThreeElements();

        // 测试5: 负数元素
        testNegativeElements();

        // 测试6: 零元素
        testZeroElement();

        // 测试7: 性能测试
        testPerformance();

        testFourElements();

        testFiveElements();

        testTwoNegativeElements();
        testThreeNegativeElements();
        testMixedThreeElements();
        testZeroWithTwoElements();
        testLargeCoefficients();
        testPlusMinusOne();
        testSymmetricFourElements();
        testSixElements();


        System.out.println("=== 所有测试完成 ===");
    }

    /**
     * 测试空集合情况
     * 期望结果: 多项式为 1，系数数组为 [1]
     */
    private static void testEmptySet() {
        System.out.println("\n测试1: 空集合");
        Set<Element> emptySet = new HashSet<>();
        Element[] coeffs = Utils.expandPolynomial(emptySet, bp);

        System.out.println("输入集合: {}");
        System.out.println("期望多项式: 1");
        System.out.println("实际系数: " + Arrays.toString(coeffs));

        assert coeffs.length == 1 : "空集合应返回长度为1的数组";
        assert coeffs[0].isEqual(bp.getZr().newOneElement()) : "空集合的常数项应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试单元素集合
     * 输入: {a}，期望结果: (x+a) = x + a
     */
    private static void testSingleElement() {
        System.out.println("\n测试2: 单元素集合");
        Set<Element> singleSet = new HashSet<>();
        Element a = bp.getZr().newElement(5); // 假设a=5
        singleSet.add(a);

        Element[] coeffs = Utils.expandPolynomial(singleSet, bp);

        System.out.println("输入集合: {5}");
        System.out.println("期望多项式: (x+5) = x + 5");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + "]");

        assert coeffs.length == 2 : "单元素集合应返回长度为2的数组";
        assert coeffs[0].isEqual(a) : "常数项应等于输入元素";
        assert coeffs[1].isEqual(bp.getZr().newOneElement()) : "一次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试两元素集合
     * 输入: {2, 3}，期望结果: (x+2)(x+3) = x² + 5x + 6
     */
    private static void testTwoElements() {
        System.out.println("\n测试3: 两元素集合");
        Set<Element> twoSet = new HashSet<>();
        Element a = bp.getZr().newElement(2);
        Element b = bp.getZr().newElement(3);
        twoSet.add(a);
        twoSet.add(b);

        Element[] coeffs = Utils.expandPolynomial(twoSet, bp);

        System.out.println("输入集合: {2, 3}");
        System.out.println("期望多项式: (x+2)(x+3) = x² + 5x + 6");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + "]");

        assert coeffs.length == 3 : "两元素集合应返回长度为3的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(6)) : "常数项应为6";
        assert coeffs[1].isEqual(bp.getZr().newElement(5)) : "一次项系数应为5";
        assert coeffs[2].isEqual(bp.getZr().newOneElement()) : "二次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试三元素集合
     * 输入: {1, 2, 3}，期望结果: (x+1)(x+2)(x+3) = x³ + 6x² + 11x + 6
     */
    private static void testThreeElements() {
        System.out.println("\n测试4: 三元素集合");
        Set<Element> threeSet = new HashSet<>();
        Element a = bp.getZr().newElement(1);
        Element b = bp.getZr().newElement(2);
        Element c = bp.getZr().newElement(3);
        threeSet.add(a);
        threeSet.add(b);
        threeSet.add(c);

        Element[] coeffs = Utils.expandPolynomial(threeSet, bp);

        System.out.println("输入集合: {1, 2, 3}");
        System.out.println("期望多项式: (x+1)(x+2)(x+3) = x³ + 6x² + 11x + 6");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + ", " + coeffs[3] + "]");

        assert coeffs.length == 4 : "三元素集合应返回长度为4的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(6)) : "常数项应为6";
        assert coeffs[1].isEqual(bp.getZr().newElement(11)) : "一次项系数应为11";
        assert coeffs[2].isEqual(bp.getZr().newElement(6)) : "二次项系数应为6";
        assert coeffs[3].isEqual(bp.getZr().newOneElement()) : "三次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试包含负数的集合
     * 输入: {-1, 2}，期望结果: (x-1)(x+2) = x² + x - 2
     */
    private static void testNegativeElements() {
        System.out.println("\n测试5: 负数元素");
        Set<Element> negSet = new HashSet<>();
        Element a = bp.getZr().newElement(-1);
        Element b = bp.getZr().newElement(2);
        negSet.add(a);
        negSet.add(b);

        Element[] coeffs = Utils.expandPolynomial(negSet, bp);

        System.out.println("输入集合: {-1, 2}");
        System.out.println("期望多项式: (x-1)(x+2) = x² + x - 2");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + "]");

        assert coeffs.length == 3 : "两元素集合应返回长度为3的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(-2)) : "常数项应为-2";
        assert coeffs[1].isEqual(bp.getZr().newElement(1)) : "一次项系数应为1";
        assert coeffs[2].isEqual(bp.getZr().newOneElement()) : "二次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试包含零元素的集合
     * 输入: {0, 3}，期望结果: (x+0)(x+3) = x(x+3) = x² + 3x
     */
    private static void testZeroElement() {
        System.out.println("\n测试6: 零元素");
        Set<Element> zeroSet = new HashSet<>();
        Element zero = bp.getZr().newZeroElement();
        Element three = bp.getZr().newElement(3);
        zeroSet.add(zero);
        zeroSet.add(three);

        Element[] coeffs = Utils.expandPolynomial(zeroSet, bp);

        System.out.println("输入集合: {0, 3}");
        System.out.println("期望多项式: x(x+3) = x² + 3x");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + "]");

        assert coeffs.length == 3 : "两元素集合应返回长度为3的数组";
        assert coeffs[0].isEqual(bp.getZr().newZeroElement()) : "常数项应为0";
        assert coeffs[1].isEqual(bp.getZr().newElement(3)) : "一次项系数应为3";
        assert coeffs[2].isEqual(bp.getZr().newOneElement()) : "二次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 性能测试
     */
    private static void testPerformance() {
        System.out.println("\n测试7: 性能测试");
        Set<Element> largeSet = new HashSet<>();

        // 创建一个较大的集合
        for (int i = 1; i <= 10; i++) {
            largeSet.add(bp.getZr().newElement(i));
        }

        long startTime = System.currentTimeMillis();
        Element[] coeffs = Utils.expandPolynomial(largeSet, bp);
        long endTime = System.currentTimeMillis();

        System.out.println("输入集合大小: " + largeSet.size());
        System.out.println("输出系数数组长度: " + coeffs.length);
        System.out.println("执行时间: " + (endTime - startTime) + "ms");
        System.out.println("✓ 性能测试完成");
    }

    /**
     * 测试四元素集合
     * 输入: {1, 2, 3, 4}，期望结果: (x+1)(x+2)(x+3)(x+4) = x⁴ + 10x³ + 35x² + 50x + 24
     */
    private static void testFourElements() {
        System.out.println("\n测试8: 四元素集合");
        Set<Element> fourSet = new HashSet<>();
        Element a = bp.getZr().newElement(1);
        Element b = bp.getZr().newElement(2);
        Element c = bp.getZr().newElement(3);
        Element d = bp.getZr().newElement(4);
        fourSet.add(a);
        fourSet.add(b);
        fourSet.add(c);
        fourSet.add(d);

        Element[] coeffs = Utils.expandPolynomial(fourSet, bp);

        System.out.println("输入集合: {1, 2, 3, 4}");
        System.out.println("期望多项式: (x+1)(x+2)(x+3)(x+4) = x⁴ + 10x³ + 35x² + 50x + 24");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + ", " + coeffs[3] + ", " + coeffs[4] + "]");

        assert coeffs.length == 5 : "四元素集合应返回长度为5的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(24)) : "常数项应为24";
        assert coeffs[1].isEqual(bp.getZr().newElement(50)) : "一次项系数应为50";
        assert coeffs[2].isEqual(bp.getZr().newElement(35)) : "二次项系数应为35";
        assert coeffs[3].isEqual(bp.getZr().newElement(10)) : "三次项系数应为10";
        assert coeffs[4].isEqual(bp.getZr().newOneElement()) : "四次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试五元素集合
     * 输入: {1, 2, 3, 4, 5}，期望结果: (x+1)(x+2)(x+3)(x+4)(x+5) = x⁵ + 15x⁴ + 85x³ + 225x² + 274x + 120
     */
    private static void testFiveElements() {
        System.out.println("\n测试9: 五元素集合");
        Set<Element> fiveSet = new HashSet<>();
        for (int i = 1; i <= 5; i++) {
            fiveSet.add(bp.getZr().newElement(i));
        }

        Element[] coeffs = Utils.expandPolynomial(fiveSet, bp);

        System.out.println("输入集合: {1, 2, 3, 4, 5}");
        System.out.println("期望多项式: (x+1)(x+2)(x+3)(x+4)(x+5) = x⁵ + 15x⁴ + 85x³ + 225x² + 274x + 120");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + ", " + coeffs[3] + ", " + coeffs[4] + ", " + coeffs[5] + "]");

        assert coeffs.length == 6 : "五元素集合应返回长度为6的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(120)) : "常数项应为120";
        assert coeffs[1].isEqual(bp.getZr().newElement(274)) : "一次项系数应为274";
        assert coeffs[2].isEqual(bp.getZr().newElement(225)) : "二次项系数应为225";
        assert coeffs[3].isEqual(bp.getZr().newElement(85)) : "三次项系数应为85";
        assert coeffs[4].isEqual(bp.getZr().newElement(15)) : "四次项系数应为15";
        assert coeffs[5].isEqual(bp.getZr().newOneElement()) : "五次项系数应为1";
        System.out.println("✓ 测试通过");
    }



    /**
     * 测试两个负数元素集合
     * 输入: {-2, -3}，期望结果: (x-2)(x-3) = x² - 5x + 6
     */
    private static void testTwoNegativeElements() {
        System.out.println("\n测试10: 两个负数元素集合");
        Set<Element> twoNegSet = new HashSet<>();
        Element a = bp.getZr().newElement(-2);
        Element b = bp.getZr().newElement(-3);
        twoNegSet.add(a);
        twoNegSet.add(b);

        Element[] coeffs = Utils.expandPolynomial(twoNegSet, bp);

        System.out.println("输入集合: {-2, -3}");
        System.out.println("期望多项式: (x-2)(x-3) = x² - 5x + 6");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + "]");

        assert coeffs.length == 3 : "两元素集合应返回长度为3的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(6)) : "常数项应为6";
        assert coeffs[1].isEqual(bp.getZr().newElement(-5)) : "一次项系数应为-5";
        assert coeffs[2].isEqual(bp.getZr().newOneElement()) : "二次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试三个负数元素集合
     * 输入: {-1, -2, -3}，期望结果: (x-1)(x-2)(x-3) = x³ - 6x² + 11x - 6
     */
    private static void testThreeNegativeElements() {
        System.out.println("\n测试11: 三个负数元素集合");
        Set<Element> threeNegSet = new HashSet<>();
        Element a = bp.getZr().newElement(-1);
        Element b = bp.getZr().newElement(-2);
        Element c = bp.getZr().newElement(-3);
        threeNegSet.add(a);
        threeNegSet.add(b);
        threeNegSet.add(c);

        Element[] coeffs = Utils.expandPolynomial(threeNegSet, bp);

        System.out.println("输入集合: {-1, -2, -3}");
        System.out.println("期望多项式: (x-1)(x-2)(x-3) = x³ - 6x² + 11x - 6");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + ", " + coeffs[3] + "]");

        assert coeffs.length == 4 : "三元素集合应返回长度为4的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(-6)) : "常数项应为-6";
        assert coeffs[1].isEqual(bp.getZr().newElement(11)) : "一次项系数应为11";
        assert coeffs[2].isEqual(bp.getZr().newElement(-6)) : "二次项系数应为-6";
        assert coeffs[3].isEqual(bp.getZr().newOneElement()) : "三次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试正负混合三元素集合
     * 输入: {-2, 1, 3}，期望结果: (x-2)(x+1)(x+3) = x³ + 2x² - 5x - 6
     */
    private static void testMixedThreeElements() {
        System.out.println("\n测试12: 正负混合三元素集合");
        Set<Element> mixedSet = new HashSet<>();
        Element a = bp.getZr().newElement(-2);
        Element b = bp.getZr().newElement(1);
        Element c = bp.getZr().newElement(3);
        mixedSet.add(a);
        mixedSet.add(b);
        mixedSet.add(c);

        Element[] coeffs = Utils.expandPolynomial(mixedSet, bp);

        System.out.println("输入集合: {-2, 1, 3}");
        System.out.println("期望多项式: (x-2)(x+1)(x+3) = x³ + 2x² - 5x - 6");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + ", " + coeffs[3] + "]");

        assert coeffs.length == 4 : "三元素集合应返回长度为4的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(-6)) : "常数项应为-6";
        assert coeffs[1].isEqual(bp.getZr().newElement(-5)) : "一次项系数应为-5";
        assert coeffs[2].isEqual(bp.getZr().newElement(2)) : "二次项系数应为2";
        assert coeffs[3].isEqual(bp.getZr().newOneElement()) : "三次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试包含零的三元素集合
     * 输入: {0, 2, 4}，期望结果: x(x+2)(x+4) = x³ + 6x² + 8x
     */
    private static void testZeroWithTwoElements() {
        System.out.println("\n测试13: 包含零的三元素集合");
        Set<Element> zeroSet = new HashSet<>();
        Element zero = bp.getZr().newZeroElement();
        Element two = bp.getZr().newElement(2);
        Element four = bp.getZr().newElement(4);
        zeroSet.add(zero);
        zeroSet.add(two);
        zeroSet.add(four);

        Element[] coeffs = Utils.expandPolynomial(zeroSet, bp);

        System.out.println("输入集合: {0, 2, 4}");
        System.out.println("期望多项式: x(x+2)(x+4) = x³ + 6x² + 8x");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + ", " + coeffs[3] + "]");

        assert coeffs.length == 4 : "三元素集合应返回长度为4的数组";
        assert coeffs[0].isEqual(bp.getZr().newZeroElement()) : "常数项应为0";
        assert coeffs[1].isEqual(bp.getZr().newElement(8)) : "一次项系数应为8";
        assert coeffs[2].isEqual(bp.getZr().newElement(6)) : "二次项系数应为6";
        assert coeffs[3].isEqual(bp.getZr().newOneElement()) : "三次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试大系数集合
     * 输入: {10, 20}，期望结果: (x+10)(x+20) = x² + 30x + 200
     */
    private static void testLargeCoefficients() {
        System.out.println("\n测试14: 大系数集合");
        Set<Element> largeSet = new HashSet<>();
        Element ten = bp.getZr().newElement(10);
        Element twenty = bp.getZr().newElement(20);
        largeSet.add(ten);
        largeSet.add(twenty);

        Element[] coeffs = Utils.expandPolynomial(largeSet, bp);

        System.out.println("输入集合: {10, 20}");
        System.out.println("期望多项式: (x+10)(x+20) = x² + 30x + 200");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + "]");

        assert coeffs.length == 3 : "两元素集合应返回长度为3的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(200)) : "常数项应为200";
        assert coeffs[1].isEqual(bp.getZr().newElement(30)) : "一次项系数应为30";
        assert coeffs[2].isEqual(bp.getZr().newOneElement()) : "二次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试分数类似效果集合（用小数表示）
     * 输入: {1, -1}，期望结果: (x+1)(x-1) = x² - 1
     */
    private static void testPlusMinusOne() {
        System.out.println("\n测试15: +1和-1集合");
        Set<Element> pmSet = new HashSet<>();
        Element one = bp.getZr().newElement(1);
        Element negOne = bp.getZr().newElement(-1);
        pmSet.add(one);
        pmSet.add(negOne);

        Element[] coeffs = Utils.expandPolynomial(pmSet, bp);

        System.out.println("输入集合: {1, -1}");
        System.out.println("期望多项式: (x+1)(x-1) = x² - 1");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + "]");

        assert coeffs.length == 3 : "两元素集合应返回长度为3的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(-1)) : "常数项应为-1";
        assert coeffs[1].isEqual(bp.getZr().newZeroElement()) : "一次项系数应为0";
        assert coeffs[2].isEqual(bp.getZr().newOneElement()) : "二次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试对称四元素集合
     * 输入: {-2, -1, 1, 2}，期望结果: (x-2)(x-1)(x+1)(x+2) = x⁴ - 5x² + 4
     */
    private static void testSymmetricFourElements() {
        System.out.println("\n测试16: 对称四元素集合");
        Set<Element> symSet = new HashSet<>();
        Element negTwo = bp.getZr().newElement(-2);
        Element negOne = bp.getZr().newElement(-1);
        Element one = bp.getZr().newElement(1);
        Element two = bp.getZr().newElement(2);
        symSet.add(negTwo);
        symSet.add(negOne);
        symSet.add(one);
        symSet.add(two);

        Element[] coeffs = Utils.expandPolynomial(symSet, bp);

        System.out.println("输入集合: {-2, -1, 1, 2}");
        System.out.println("期望多项式: (x-2)(x-1)(x+1)(x+2) = x⁴ - 5x² + 4");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + ", " + coeffs[3] + ", " + coeffs[4] + "]");

        assert coeffs.length == 5 : "四元素集合应返回长度为5的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(4)) : "常数项应为4";
        assert coeffs[1].isEqual(bp.getZr().newZeroElement()) : "一次项系数应为0";
        assert coeffs[2].isEqual(bp.getZr().newElement(-5)) : "二次项系数应为-5";
        assert coeffs[3].isEqual(bp.getZr().newZeroElement()) : "三次项系数应为0";
        assert coeffs[4].isEqual(bp.getZr().newOneElement()) : "四次项系数应为1";
        System.out.println("✓ 测试通过");
    }

    /**
     * 测试六元素集合（1到6）
     * 输入: {1, 2, 3, 4, 5, 6}，期望结果: (x+1)(x+2)(x+3)(x+4)(x+5)(x+6) = x⁶ + 21x⁵ + 175x⁴ + 735x³ + 1624x² + 1764x + 720
     */
    private static void testSixElements() {
        System.out.println("\n测试17: 六元素集合");
        Set<Element> sixSet = new HashSet<>();
        for (int i = 1; i <= 6; i++) {
            sixSet.add(bp.getZr().newElement(i));
        }

        Element[] coeffs = Utils.expandPolynomial(sixSet, bp);

        System.out.println("输入集合: {1, 2, 3, 4, 5, 6}");
        System.out.println("期望多项式: (x+1)(x+2)(x+3)(x+4)(x+5)(x+6) = x⁶ + 21x⁵ + 175x⁴ + 735x³ + 1624x² + 1764x + 720");
        System.out.println("实际系数: [" + coeffs[0] + ", " + coeffs[1] + ", " + coeffs[2] + ", " + coeffs[3] + ", " + coeffs[4] + ", " + coeffs[5] + ", " + coeffs[6] + "]");

        assert coeffs.length == 7 : "六元素集合应返回长度为7的数组";
        assert coeffs[0].isEqual(bp.getZr().newElement(720)) : "常数项应为720";
        assert coeffs[1].isEqual(bp.getZr().newElement(1764)) : "一次项系数应为1764";
        assert coeffs[2].isEqual(bp.getZr().newElement(1624)) : "二次项系数应为1624";
        assert coeffs[3].isEqual(bp.getZr().newElement(735)) : "三次项系数应为735";
        assert coeffs[4].isEqual(bp.getZr().newElement(175)) : "四次项系数应为175";
        assert coeffs[5].isEqual(bp.getZr().newElement(21)) : "五次项系数应为21";
        assert coeffs[6].isEqual(bp.getZr().newOneElement()) : "六次项系数应为1";
        System.out.println("✓ 测试通过");
    }


    /**
     * 辅助方法：验证多项式计算的正确性
     * 通过代入具体值验证多项式
     */
    private boolean verifyPolynomial(Set<Element> X, Element[] coeffs, Element testValue) {
        // 计算原多项式 (testValue + x1)(testValue + x2)...(testValue + xn)
        Element expected = bp.getZr().newOneElement();
        for (Element x : X) {
            expected = expected.mul(testValue.add(x));
        }

        // 计算展开后的多项式在testValue处的值
        Element actual = bp.getZr().newZeroElement();
        Element power = bp.getZr().newOneElement();

        for (int i = 0; i < coeffs.length; i++) {
            actual = actual.add(coeffs[i].mul(power));
            power = power.mul(testValue);
        }

        return expected.isEqual(actual);
    }

    /**
     * 额外验证测试：通过代入值验证多项式正确性
     */
    public void testPolynomialVerification() {
        System.out.println("\n=== 多项式验证测试 ===");

        Set<Element> testSet = new HashSet<>();
        testSet.add(bp.getZr().newElement(2));
        testSet.add(bp.getZr().newElement(3));

        Element[] coeffs = Utils.expandPolynomial(testSet, bp);

        // 用多个值验证多项式
        Element[] testValues = {
                bp.getZr().newElement(0),
                bp.getZr().newElement(1),
                bp.getZr().newElement(-1),
                bp.getZr().newElement(5)
        };

        for (Element testValue : testValues) {
            boolean isValid = verifyPolynomial(testSet, coeffs, testValue);
            System.out.println("代入x=" + testValue + "验证: " + (isValid ? "✓ 通过" : "✗ 失败"));
            assert isValid : "多项式验证失败";
        }

        System.out.println("✓ 多项式验证测试完成");
    }
}
