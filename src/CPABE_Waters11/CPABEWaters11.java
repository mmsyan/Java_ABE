package CPABE_Waters11;

import Utils.ConversionUtils;
import Utils.PropertiesUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;

public class CPABEWaters11 {

    private int universe;
    private Pairing bp;
    private Element g; //G1
    private Element alpha; //Zr
    private Element a;
    private Element eggAlpha;  //Gt
    private Element ga; // G1
    private Element[] h;

    public Pairing getBp() {
        return this.bp;
    }

    public CPABEWaters11(int u) {
        this.universe = u;
    }

    public void setUp(String pairingFilePath) {
        this.bp = PairingFactory.getPairing(pairingFilePath);
        this.g = bp.getG1().newRandomElement().getImmutable(); // g <- G1
        this.alpha = bp.getZr().newRandomElement().getImmutable(); // alpha <- Zr
        this.a = bp.getZr().newRandomElement().getImmutable(); // alpha <- Zr
        this.eggAlpha = bp.pairing(g, g).powZn(alpha).getImmutable(); // e(g, g)^alpha
        this.ga = g.powZn(a).getImmutable();
        this.h = new Element[universe];
        for (int i = 0; i < universe; i++) {
            h[i] = bp.getG1().newRandomElement().getImmutable(); // h1 h2 …… hU
        }
    }

    public void keyGeneration(int[] userAttributes, String skFilePath) {
        Properties skProperties = new Properties();

        Element t = this.bp.getZr().newRandomElement().getImmutable(); // t <- Zr

        Element K = this.g.powZn(alpha).mul(ga.powZn(t)); // K = g^alpha * g^at
        Element L = g.powZn(t).getImmutable(); // L = g^t
        skProperties.setProperty("K", ConversionUtils.bytes2String(K.toBytes()));
        skProperties.setProperty("L", ConversionUtils.bytes2String(L.toBytes()));

        for (int x : userAttributes) { // for each attribute j ∈ S(user Attributes)
            Element Kx = h[x].powZn(t);
            skProperties.setProperty("Kx"+x, ConversionUtils.bytes2String(Kx.toBytes()));
        }

        PropertiesUtils.store(skProperties, skFilePath);
    }

    public void encrypt(CPABELewkoWatersLSSS messageMatrix, Element message, String ctFilePath) {
        Properties ctProperties = new Properties();

        // random vector v = [s, y2, y3, ……, yn] <—— Zp
        Element[] v = new Element[messageMatrix.n];
        for (int i = 0; i < v.length; i++) {
            v[i] = bp.getZr().newRandomElement().getImmutable();
        }

        Element eggAlphaS = eggAlpha.powZn(v[0]).getImmutable();
        System.out.println("eggAlphaS-e(g,g)^(alpha*s): " + eggAlphaS);
        Element C = message.mul(eggAlphaS); // C = M * (e(g,g)^alpha)^s
        System.out.println("加密阶段加密得到的C：" + C);
        Element CPrime = g.powZn(v[0]); // C' = g^s
        ctProperties.setProperty("C", ConversionUtils.bytes2String(C.toBytes()));
        ctProperties.setProperty("CPrime", ConversionUtils.bytes2String(CPrime.toBytes()));

        for (int i = 0; i < messageMatrix.l; i++) {
            Element[] Mi = Arrays.copyOf(messageMatrix.Mi(i), messageMatrix.Mi(i).length);
            Element lambdai = bp.getZr().newZeroElement().getImmutable();
            Element ri = bp.getZr().newRandomElement().getImmutable();
            for (int j = 0; j < messageMatrix.n; j++) {
                lambdai = lambdai.add(Mi[j].mul(v[j]));
            }
            Element Ci = (ga.powZn(lambdai)).div(h[messageMatrix.rhoi(i)].powZn(ri)); // Ci = g^(a*lambdai) / h_rho^ri
            Element Di = g.powZn(ri).getImmutable(); // Di = g^(ri)
            ctProperties.setProperty("Ci"+i, ConversionUtils.bytes2String(Ci.toBytes()));
            ctProperties.setProperty("Di"+i, ConversionUtils.bytes2String(Di.toBytes()));
        }

        PropertiesUtils.store(ctProperties, ctFilePath);
    }

    public Element decrypt(CPABELewkoWatersLSSS messageMatrix, int[] userAttributes, String skFilePath, String ctFilePath) {
        Properties skProperties = PropertiesUtils.load(skFilePath);
        Properties ctProperties = PropertiesUtils.load(ctFilePath);

        String KStr = skProperties.getProperty("K");
        Element K = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(KStr)).getImmutable();
        String LStr = skProperties.getProperty("L");
        Element L = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(LStr)).getImmutable();
        HashMap<Integer, Element> SecretKeyKx = new HashMap<>();
        for (int x : userAttributes) { // for each attribute j ∈ S(user Attributes)
            String KxStr = skProperties.getProperty("Kx"+x);
            Element kx = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(KxStr)).getImmutable();
            SecretKeyKx.put(x, kx);
        }

        String CStr = ctProperties.getProperty("C");
        Element C = bp.getGT().newElementFromBytes(ConversionUtils.String2Bytes(CStr)).getImmutable();
        System.out.println("解密阶段恢复出来的C：" + C);

        String CPrimeStr = ctProperties.getProperty("CPrime");
        Element CPrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CPrimeStr)).getImmutable();

        HashMap<Integer, Element> CiphertextCi = new HashMap<>();
        HashMap<Integer, Element> CiphertextDi = new HashMap<>();
        for (int i = 0; i < messageMatrix.l; i++) {
            String CiStr = ctProperties.getProperty("Ci"+i);
            CiphertextCi.put(i, bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CiStr)).getImmutable());
            String DiStr = ctProperties.getProperty("Di"+i);
            CiphertextDi.put(i, bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(DiStr)).getImmutable());
        }

        if (!messageMatrix.isSatisfied(userAttributes)) {
            System.out.println("解密失败！属性策略不符合。");
            return null;
        }
        else {
            Element eggAlphaSRecover = messageMatrix.recoverSecret(userAttributes, CPrime, K, L, CiphertextCi, CiphertextDi, SecretKeyKx); // e(g,g)^(alpha*s)
            System.out.println("eggAlphaSRecover-e(g,g)^(alpha*s): " + eggAlphaSRecover);
            return C.div(eggAlphaSRecover); // C = M*e(g,g)^(alpha*s) , M = C / eggAlphaSRecover
        }
    }

}
