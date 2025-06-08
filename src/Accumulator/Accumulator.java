package Accumulator;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashSet;
import java.util.Set;

public class Accumulator {
    private Pairing bp;
    private Element g1;
    private Element g2;
    private Element[] g1Powers;
    private Element[] g2Powers;
    private Element s;
    private int maxCapacity;

    public Accumulator(String pairingFilePath, int maxCapacity) {
        this.bp = PairingFactory.getPairing(pairingFilePath);
        this.maxCapacity = maxCapacity;
    }

    public void Setup() {
        this.g1 = bp.getG1().newRandomElement().getImmutable();
        this.g2 = bp.getG2().newRandomElement().getImmutable();
        this.s = bp.getZr().newRandomElement().getImmutable();
        this.g1Powers = new Element[maxCapacity + 1];
        this.g2Powers = new Element[maxCapacity + 1];

        Element currentS = bp.getZr().newOneElement();
        // g1^(s^0), g1^(s^1), g1^(s^2), ... , g1^(s^t), t = maxCapacity
        // g2^(s^0), g2^(s^1), g2^(s^2), ... , g2^(s^t), t = maxCapacity
        for (int i = 0; i <= maxCapacity; i++) {
            this.g1Powers[i] = g1.powZn(currentS).getImmutable();
            this.g2Powers[i] = g2.powZn(currentS).getImmutable();
            // 修正：应该是 currentS = currentS.mul(s)，而不是 currentS.mul(currentS)
            if (i < maxCapacity) {
                currentS = currentS.mul(s).getImmutable();
            }
        }
    }

    public Element Commit(Set<Element> X) {
        // Ax = g1^{(x1+s)(x2+s)...(x|X|+s)}
        // 方法1: 先计算指数的乘积，再做一次幂运算
        Element exponent = bp.getZr().newOneElement(); // 从1开始
        for (Element x : X) {
            Element temp = x.add(s); // x + s
            exponent = exponent.mul(temp); // 累乘: (x1+s)(x2+s)...(x|X|+s)
        }
        Element Ax = g1.powZn(exponent); // g1^{累乘结果}
        return Ax.getImmutable();
    }

    public Element Add(Element Ax, Set<Element> X, Set<Element> I) {
        // checks X ∩ I = 空集合
        // Ax' = Ax^{(xi+s)(xi+s)...(xi+s)}, xi \in I
        Element AxPrime = Ax.duplicate();
        Element exponent = bp.getZr().newOneElement();
        for (Element xi : I) {
            Element temp = xi.add(s);
            exponent = exponent.mul(temp);
        }
        return AxPrime.powZn(exponent).getImmutable();
    }

    public Element MemProve(Set<Element> X, Element y) {
        Element piY = g1.duplicate();
        Element exponent = bp.getZr().newOneElement();
        for (Element x : X) {
            if (!x.isEqual(y)) {
                Element temp = x.add(s);
                exponent = exponent.mul(temp); // 修正：应该累乘
            }
        }
        return piY.powZn(exponent).getImmutable();
    }

    public boolean MemVerify(Element Ax, Element y, Element piY) {
        Element left = bp.pairing(piY, g2.powZn(y.add(s)));
        Element right = bp.pairing(Ax, g2);
        return left.isEqual(right); // 修正：使用 isEqual 而不是 ==
    }

    // Getter methods for testing
    public Element getG1() { return g1; }
    public Element getG2() { return g2; }
    public Element getS() { return s; }
    public Pairing getPairing() { return bp; }

    public static void main(String[] args) {
        System.out.println("=== 密码学累加器测试开始 ===\n");

        // 初始化累加器
        Accumulator accumulator = new Accumulator("a.properties", 10);
        accumulator.Setup();

        System.out.println("✓ 累加器初始化完成");
        System.out.println("最大容量: " + accumulator.maxCapacity);
        System.out.println();

        // 测试案例1: 基本提交和成员证明
        testBasicCommitAndProof(accumulator);

        // 测试案例2: 添加元素
        testAddElements(accumulator);

        // 测试案例3: 非成员验证
        testNonMembershipVerification(accumulator);

        // 测试案例4: 空集合处理
        testEmptySetHandling(accumulator);

        // 测试案例5: 大量元素测试
        testLargeSetHandling(accumulator);

        // 测试案例6: 边界条件测试
        testBoundaryConditions(accumulator);

        System.out.println("\n=== 所有测试完成 ===");
    }

    private static void testBasicCommitAndProof(Accumulator acc) {
        System.out.println("【测试案例1: 基本提交和成员证明】");

        // 创建测试集合 X = {1, 2, 3}
        Set<Element> X = new HashSet<>();
        Element e1 = acc.getPairing().getZr().newElement(1).getImmutable();
        Element e2 = acc.getPairing().getZr().newElement(2).getImmutable();
        Element e3 = acc.getPairing().getZr().newElement(3).getImmutable();
        X.add(e1);
        X.add(e2);
        X.add(e3);

        // 提交
        Element Ax = acc.Commit(X);
        System.out.println("✓ 集合 X = {1, 2, 3} 提交成功");

        // 为元素 2 生成成员证明
        Element proof2 = acc.MemProve(X, e2);
        boolean isValid2 = acc.MemVerify(Ax, e2, proof2);
        System.out.println("✓ 元素 2 的成员证明: " + (isValid2 ? "有效" : "无效"));

        // 为元素 1 生成成员证明
        Element proof1 = acc.MemProve(X, e1);
        boolean isValid1 = acc.MemVerify(Ax, e1, proof1);
        System.out.println("✓ 元素 1 的成员证明: " + (isValid1 ? "有效" : "无效"));

        System.out.println();
    }

    private static void testAddElements(Accumulator acc) {
        System.out.println("【测试案例2: 添加元素】");

        // 初始集合 X = {5, 6}
        Set<Element> X = new HashSet<>();
        Element e5 = acc.getPairing().getZr().newElement(5).getImmutable();
        Element e6 = acc.getPairing().getZr().newElement(6).getImmutable();
        X.add(e5);
        X.add(e6);

        Element Ax = acc.Commit(X);
        System.out.println("✓ 初始集合 X = {5, 6} 提交完成");

        // 添加元素 I = {7, 8}
        Set<Element> I = new HashSet<>();
        Element e7 = acc.getPairing().getZr().newElement(7).getImmutable();
        Element e8 = acc.getPairing().getZr().newElement(8).getImmutable();
        I.add(e7);
        I.add(e8);

        Element AxPrime = acc.Add(Ax, X, I);
        System.out.println("✓ 添加元素 I = {7, 8} 完成");

        // 验证新集合 X' = {5, 6, 7, 8}
        Set<Element> XPrime = new HashSet<>(X);
        XPrime.addAll(I);

        // 验证原有元素
        Element proof5 = acc.MemProve(XPrime, e5);
        boolean isValid5 = acc.MemVerify(AxPrime, e5, proof5);
        System.out.println("✓ 原有元素 5 验证: " + (isValid5 ? "有效" : "无效"));

        // 验证新添加元素
        Element proof7 = acc.MemProve(XPrime, e7);
        boolean isValid7 = acc.MemVerify(AxPrime, e7, proof7);
        System.out.println("✓ 新元素 7 验证: " + (isValid7 ? "有效" : "无效"));

        System.out.println();
    }

    private static void testNonMembershipVerification(Accumulator acc) {
        System.out.println("【测试案例3: 非成员验证】");

        // 集合 X = {10, 20, 30}
        Set<Element> X = new HashSet<>();
        Element e10 = acc.getPairing().getZr().newElement(10).getImmutable();
        Element e20 = acc.getPairing().getZr().newElement(20).getImmutable();
        Element e30 = acc.getPairing().getZr().newElement(30).getImmutable();
        X.add(e10);
        X.add(e20);
        X.add(e30);

        Element Ax = acc.Commit(X);

        // 测试不在集合中的元素 99
        Element e99 = acc.getPairing().getZr().newElement(99).getImmutable();
        Element falseProof = acc.MemProve(X, e99); // 这会生成一个错误的证明
        boolean shouldBeFalse = acc.MemVerify(Ax, e99, falseProof);
        System.out.println("✓ 非成员元素 99 验证: " + (shouldBeFalse ? "错误地通过" : "正确地拒绝"));

        System.out.println();
    }

    private static void testEmptySetHandling(Accumulator acc) {
        System.out.println("【测试案例4: 空集合处理】");

        // 测试空集合
        Set<Element> emptySet = new HashSet<>();
        Element emptyCommit = acc.Commit(emptySet);
        System.out.println("✓ 空集合提交完成");

        // 向空集合添加元素
        Set<Element> I = new HashSet<>();
        Element e42 = acc.getPairing().getZr().newElement(42).getImmutable();
        I.add(e42);

        Element newCommit = acc.Add(emptyCommit, emptySet, I);
        Element proof42 = acc.MemProve(I, e42);
        boolean isValid42 = acc.MemVerify(newCommit, e42, proof42);
        System.out.println("✓ 向空集合添加元素 42 后验证: " + (isValid42 ? "有效" : "无效"));

        System.out.println();
    }

    private static void testLargeSetHandling(Accumulator acc) {
        System.out.println("【测试案例5: 大量元素测试】");

        // 创建包含多个元素的集合
        Set<Element> largeSet = new HashSet<>();
        for (int i = 100; i <= 105; i++) {
            largeSet.add(acc.getPairing().getZr().newElement(i).getImmutable());
        }

        long startTime = System.currentTimeMillis();
        Element largeCommit = acc.Commit(largeSet);
        long commitTime = System.currentTimeMillis() - startTime;
        System.out.println("✓ 大集合 (6个元素) 提交完成，耗时: " + commitTime + "ms");

        // 随机验证其中一个元素
        Element testElement = acc.getPairing().getZr().newElement(103).getImmutable();
        startTime = System.currentTimeMillis();
        Element proof = acc.MemProve(largeSet, testElement);
        boolean isValid = acc.MemVerify(largeCommit, testElement, proof);
        long verifyTime = System.currentTimeMillis() - startTime;
        System.out.println("✓ 元素 103 验证: " + (isValid ? "有效" : "无效") + "，耗时: " + verifyTime + "ms");

        System.out.println();
    }

    private static void testBoundaryConditions(Accumulator acc) {
        System.out.println("【测试案例6: 边界条件测试】");

        // 测试单元素集合
        Set<Element> singleSet = new HashSet<>();
        Element single = acc.getPairing().getZr().newElement(999).getImmutable();
        singleSet.add(single);

        Element singleCommit = acc.Commit(singleSet);
        Element singleProof = acc.MemProve(singleSet, single);
        boolean singleValid = acc.MemVerify(singleCommit, single, singleProof);
        System.out.println("✓ 单元素集合验证: " + (singleValid ? "有效" : "无效"));

        // 测试重复元素（Set会自动去重）
        Set<Element> duplicateSet = new HashSet<>();
        Element dup = acc.getPairing().getZr().newElement(777).getImmutable();
        duplicateSet.add(dup);
        duplicateSet.add(dup); // 重复添加

        Element dupCommit = acc.Commit(duplicateSet);
        Element dupProof = acc.MemProve(duplicateSet, dup);
        boolean dupValid = acc.MemVerify(dupCommit, dup, dupProof);
        System.out.println("✓ 重复元素集合验证: " + (dupValid ? "有效" : "无效"));
        System.out.println("  (实际集合大小: " + duplicateSet.size() + ")");

        System.out.println();
    }
}