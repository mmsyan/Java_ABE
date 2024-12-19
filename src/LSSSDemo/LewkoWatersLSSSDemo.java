package LSSSDemo;

import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

public class LewkoWatersLSSSDemo {
    // 案例1: https://zhuanlan.zhihu.com/p/582894634?s_r=0
    public static void testCase1() {
        LewkoWatersLSSS.Node root = new LewkoWatersLSSS.Node(2, null);
        LewkoWatersLSSS.Node lay1 = new LewkoWatersLSSS.Node(2, null);
        LewkoWatersLSSS.Node lay2 = new LewkoWatersLSSS.Node(1, null);
        LewkoWatersLSSS.Node a = new LewkoWatersLSSS.Node(1);
        LewkoWatersLSSS.Node b = new LewkoWatersLSSS.Node(2);
        LewkoWatersLSSS.Node c = new LewkoWatersLSSS.Node(3);
        LewkoWatersLSSS.Node d = new LewkoWatersLSSS.Node(4);
        lay1.addChild(a, b);
        lay2.addChild(c, d);
        root.addChild(lay1, lay2);

        LewkoWatersLSSS demo1 = new LewkoWatersLSSS(root, PairingFactory.getPairing("a.properties"));
        demo1.printLSSSMatrix();
        System.out.println("{1} is not satisfied: " + demo1.isSatisfied(new int[]{1}));
        System.out.println("{2} is not satisfied: " + demo1.isSatisfied(new int[]{2}));
        System.out.println("{2, 3, 4} is not satisfied: " + demo1.isSatisfied(new int[]{2, 3, 4}));
        System.out.println("{1, 2, 3} is satisfied: " + demo1.isSatisfied(new int[]{1, 2, 3}));
        System.out.println("{1, 2, 4} is satisfied: " + demo1.isSatisfied(new int[]{1, 2, 4}));
        System.out.println("{1, 2, 3, 4} is satisfied: " + demo1.isSatisfied(new int[]{1, 2, 3, 4}));

        System.out.println(Arrays.toString(demo1.computeWVector(new int[]{1, 2, 3})));
        System.out.println(Arrays.toString(demo1.computeWVector(new int[]{1, 2, 4})));
        System.out.println(Arrays.toString(demo1.computeWVector(new int[]{1, 2, 3, 4})));

    }

    // 案例2: https://blog.csdn.net/qq_36291381/article/details/109703720
    // 目前这个案例当中存在致命的缺陷：A | D | E三个属性无法正确解密，因为矩阵会线性相关
    public static void testCase2() {
        LewkoWatersLSSS.Node root = new LewkoWatersLSSS.Node(2, null);
        LewkoWatersLSSS.Node e = new LewkoWatersLSSS.Node(5); LewkoWatersLSSS.Node lay1Or = new LewkoWatersLSSS.Node(1, null); root.addChild(e, lay1Or);
        LewkoWatersLSSS.Node lay2Or = new LewkoWatersLSSS.Node(1, null); LewkoWatersLSSS.Node lay2And = new LewkoWatersLSSS.Node(2, null);lay1Or.addChild(lay2Or, lay2And);
        LewkoWatersLSSS.Node lay3And1 = new LewkoWatersLSSS.Node(2, null);
        LewkoWatersLSSS.Node lay3And2 = new LewkoWatersLSSS.Node(2, null);lay2Or.addChild(lay3And1, lay3And2);
        LewkoWatersLSSS.Node lay3Or1 = new LewkoWatersLSSS.Node(1, null);
        LewkoWatersLSSS.Node lay3Or2 = new LewkoWatersLSSS.Node(1, null);lay2And.addChild(lay3Or1, lay3Or2);
        LewkoWatersLSSS.Node a1 = new LewkoWatersLSSS.Node(1);
        LewkoWatersLSSS.Node b1 = new LewkoWatersLSSS.Node(2); lay3And1.addChild(a1, b1);
        LewkoWatersLSSS.Node c1 = new LewkoWatersLSSS.Node(3);
        LewkoWatersLSSS.Node d1 = new LewkoWatersLSSS.Node(4); lay3And2.addChild(c1, d1);
        LewkoWatersLSSS.Node a2 = new LewkoWatersLSSS.Node(1);
        LewkoWatersLSSS.Node b2 = new LewkoWatersLSSS.Node(2); lay3Or1.addChild(a2, b2);
        LewkoWatersLSSS.Node c2 = new LewkoWatersLSSS.Node(3);
        LewkoWatersLSSS.Node d2 = new LewkoWatersLSSS.Node(4); lay3Or2.addChild(c2, d2);

        LewkoWatersLSSS demo2 = new LewkoWatersLSSS(root, PairingFactory.getPairing("a.properties"));
        demo2.printLSSSMatrix();
    }

    public static void testCase3() {

    }

    public static void main(String[] args) {
        testCase1();
    }
}
