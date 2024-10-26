package BLS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class BLSSignature {
    public static void main(String[] args) {
        // Set Up
        Pairing bp = PairingFactory.getPairing("a.properties");

        // Key Generation
        Element g = bp.getG1().newRandomElement().getImmutable(); // g <- G1
        Element x = bp.getZr().newRandomElement().getImmutable(); // secret key: x <- Zr
        Element g_x = g.powZn(x);  // public key: g^x

        // Signature
        String message = "BLS Signature Demo Test";
        byte[] message_bytes = message.getBytes();
        Element h = bp.getG1().newElementFromHash(message_bytes, 0, message_bytes.length).getImmutable();
        Element sigma = h.powZn(x); // sigma = h^x; signature = (m, sigma)

        // Verification
        Element verification_left = bp.pairing(sigma, g);
        Element verification_right = bp.pairing(h, g_x);
        if (verification_left.isEqual(verification_right)) {
            System.out.println("(m, sigma) is a valid signature of message m.");
            System.out.println(sigma);
        }
        else {
            System.out.println("(m, sigma) is an invalid signature of message m!");
        }
    }
}
