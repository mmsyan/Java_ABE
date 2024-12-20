package CPABE_Waters11;

import CPABE_Waters11.CPABELewkoWatersLSSS.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

public class CPABELewkoWatersLSSSDemo {

    public static Node getTree1() {
        Node root = new CPABELewkoWatersLSSS.Node(2, null);
        Node lay1 = new CPABELewkoWatersLSSS.Node(2, null);
        Node lay2 = new CPABELewkoWatersLSSS.Node(1, null);
        Node a = new CPABELewkoWatersLSSS.Node(1);
        Node b = new CPABELewkoWatersLSSS.Node(2);
        Node c = new CPABELewkoWatersLSSS.Node(3);
        Node d = new CPABELewkoWatersLSSS.Node(4);
        lay1.addChild(a, b);
        lay2.addChild(c, d);
        root.addChild(lay1, lay2);
        return root;
    }

    public static void testCase1() {
        Node root = getTree1();
        CPABELewkoWatersLSSS demo1 = new CPABELewkoWatersLSSS(root, PairingFactory.getPairing("a.properties"));
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

    public static Node getTree2() {
        Node root = new CPABELewkoWatersLSSS.Node(2, null);
        Node e = new Node(5); Node lay1Or = new Node(1, null); root.addChild(e, lay1Or);
        Node lay2Or = new Node(1, null); Node lay2And = new Node(2, null);lay1Or.addChild(lay2Or, lay2And);
        Node lay3And1 = new Node(2, null);
        Node lay3And2 = new Node(2, null);lay2Or.addChild(lay3And1, lay3And2);
        Node lay3Or1 = new Node(1, null);
        Node lay3Or2 = new Node(1, null);lay2And.addChild(lay3Or1, lay3Or2);
        Node a1 = new Node(1);
        Node b1 = new Node(2); lay3And1.addChild(a1, b1);
        Node c1 = new Node(3);
        Node d1 = new Node(4); lay3And2.addChild(c1, d1);
        Node a2 = new Node(1);
        Node b2 = new Node(2); lay3Or1.addChild(a2, b2);
        Node c2 = new Node(3);
        Node d2 = new Node(4); lay3Or2.addChild(c2, d2);
        return root;
    }

    // 案例2: https://blog.csdn.net/qq_36291381/article/details/109703720
    public static void testCase2() {
        Node root = getTree2();

        CPABELewkoWatersLSSS demo2 = new CPABELewkoWatersLSSS(root, PairingFactory.getPairing("a.properties"));
        demo2.printLSSSMatrix();

        System.out.println("{1} is not satisfied: " + demo2.isSatisfied(new int[]{1}));
        System.out.println("{2} is not satisfied: " + demo2.isSatisfied(new int[]{2}));
        System.out.println("{2, 3, 4} is not satisfied: " + demo2.isSatisfied(new int[]{2, 3, 4}));
        System.out.println("{1, 2, 3, 4} is not satisfied: " + demo2.isSatisfied(new int[]{1, 2, 3, 4}));
        System.out.println("{5, 1, 2} is satisfied: " + demo2.isSatisfied(new int[]{5, 1, 2}));
        System.out.println("{5, 1, 3} is satisfied: " + demo2.isSatisfied(new int[]{5, 1, 3}));
        System.out.println("{5, 1, 2, 3} is satisfied: " + demo2.isSatisfied(new int[]{5, 1, 2, 3}));

        System.out.println(Arrays.toString(demo2.computeWVector(new int[]{5, 1, 2})));
        System.out.println(Arrays.toString(demo2.computeWVector(new int[]{5, 1, 3})));
        System.out.println(Arrays.toString(demo2.computeWVector(new int[]{5, 1, 2, 3})));
    }

    public static void main(String[] args) {
        testCase2();
    }
}
