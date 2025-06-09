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

    private Element Xs(Set<Element> X, Element s) {
        Element result = bp.getZr().newOneElement();
        for (Element x : X) {
            result.mul(s.add(x));
        }
        return result;
    }

    public Element Add(Element Ax, Set<Element> X, Set<Element> I) {
        // checks X ∩ I = 空集合
        // Ax' = Ax^{(xi+s)(xi+s)...(xi+s)}, xi \in I
        Element AxPrime = Ax.duplicate();
        return AxPrime.powZn(Xs(I, s)).getImmutable();
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


}