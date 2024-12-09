package CPABE_Waters11;

import Utils.ConversionUtils;
import Utils.MathUtils;
import Utils.PropertiesUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Properties;

public class CPABEWaters11Demo {

    private int universe;
    private Pairing bp;
    private Element g; //G1
    private Element alpha; //Zr
    private Element a;
    private Element eggalpha;  //Gt
    private Element ga; // G1
    private Element[] h;

    public CPABEWaters11Demo(int u) {
        this.universe = u;
    }

    public void setUp(String pairingFilePath) {
        this.bp = PairingFactory.getPairing(pairingFilePath);
        this.g = bp.getG1().newRandomElement().getImmutable(); // g <- G1
        this.alpha = bp.getZr().newRandomElement().getImmutable(); // alpha <- Zr
        this.a = bp.getZr().newRandomElement().getImmutable(); // alpha <- Zr
        this.eggalpha = bp.pairing(g, g).powZn(alpha).getImmutable(); // e(g, g)^alpha
        this.ga = g.powZn(a).getImmutable();
        this.h = new Element[universe];
        for (int i = 0; i < universe; i++) {
            h[i] = bp.getZr().newRandomElement().getImmutable();
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

    public void encrypt(LewkoWatersLSSS.LewkoWatersLSSSMatrix messageMatrix, Element message, String ctFilePath) {
        Properties ctProperties = new Properties();

        Element[] v = new Element[messageMatrix.n];
        for (int i = 0; i < v.length; i++) {
            v[i] = bp.getZr().newRandomElement().getImmutable();
        }

        Element C = message.mul(eggalpha.powZn(v[0]));
        Element CPrime = g.powZn(v[0]);
        ctProperties.setProperty("C", ConversionUtils.bytes2String(C.toBytes()));
        ctProperties.setProperty("CPrime", ConversionUtils.bytes2String(CPrime.toBytes()));

        for (int i = 0; i < messageMatrix.l; i++) {
            Element[] Mi = Arrays.copyOf(messageMatrix.Mi(i), messageMatrix.Mi(i).length);
            Element lambdai = bp.getZr().newZeroElement().getImmutable();
            Element ri = bp.getZr().newRandomElement().getImmutable();
            for (int j = 0; j < messageMatrix.n; j++) {
                lambdai = lambdai.add(Mi[j].mul(v[j]));
            }
            Element Ci = ga.powZn(lambdai).div(h[messageMatrix.rhoi(i)].powZn(ri));
            Element Di = g.powZn(ri).getImmutable();
            ctProperties.setProperty("Ci"+i, ConversionUtils.bytes2String(Ci.toBytes()));
            ctProperties.setProperty("Di"+i, ConversionUtils.bytes2String(Di.toBytes()));
        }

        PropertiesUtils.store(ctProperties, ctFilePath);
    }

    public Element decrypt(LewkoWatersLSSS.LewkoWatersLSSSMatrix messageMatrix, int[] userAttributes, String skFilePath, String ctFilePath) {
        Properties skProperties = PropertiesUtils.load(skFilePath);
        Properties ctProperties = PropertiesUtils.load(ctFilePath);

        String KStr = skProperties.getProperty("K");
        Element K = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(KStr)).getImmutable();
        String LStr = ctProperties.getProperty("L");
        Element L = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(LStr)).getImmutable();

        String CStr = ctProperties.getProperty("CPrime");
        Element C = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CStr)).getImmutable();
        String CPrimeStr = ctProperties.getProperty("CPrime");
        Element CPrime = bp.getG1().newElementFromBytes(ConversionUtils.String2Bytes(CPrimeStr)).getImmutable();

        Element eggAlphasRecover;
        return C.div(eggAlphasRecover);

    }

}
