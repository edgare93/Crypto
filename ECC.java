import java.math.BigInteger;
import java.util.Random;
import java.lang.Math;

public class ECC {
    private static final BigInteger _0 = BigInteger.valueOf(0L);
    private static final BigInteger _1 = BigInteger.valueOf(1L);
    //private static final BigInteger _2 = BigInteger.valueOf(2L);
    private static final BigInteger _3 = BigInteger.valueOf(3L);
    public static final BigInteger p = _1.shiftLeft(521).subtract(_1);
    
    //d was changed to public so I could access it for qDSA, just making this comment to remember that change
    public static final BigInteger d = BigInteger.valueOf(-376014L);
    // Remember to change this back
    public static final BigInteger r = _1.shiftLeft(519).subtract(new BigInteger("337554763258501705789107630418782636071" +
            "904961214051226618635150085779108655765", 10));
    /**
     * Point "at infinity" (i.e. neutral element) on  E_521.
     */
    public static final BigInteger[] O = new BigInteger[] {_0, _1};

    /**
     * Compute a square root of v mod p with a specified least significant bit, if such a root exists.
     *
     * @param   v   the radicand.
     * @param   p   the modulus (must satisfy p mod 4 = 3).
     * @param   lsb desired least significant bit (true: 1, false: 0).
     * @return  a square root r of v mod p with r mod 2 = 1 iff lsb = true
     *          if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return _0;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(_1), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * Determine if a given affine coordinate pair P = (x, y) defines a point on the curve E_521.
     *
     * @param P
     * @return whether P is a point on E_521.
     */
    public static boolean isPoint(BigInteger[] P) {
        BigInteger x = P[0], x2 = x.multiply(x).mod(p), y = P[1], y2 = y.multiply(y).mod(p);
        return x2.add(y2).subtract(_1.add(d.multiply(x2).multiply(y2))).mod(p).signum() == 0;
    }

    /**
     * Build a point P = (x, y) on (the subgroup of prime order r of) E_521 given x and the lsb of y.
     *
     * @return P.
     */
    public static BigInteger[] makePoint(BigInteger x, boolean ybit) {
        BigInteger[] P = new BigInteger[] {x, null};
        BigInteger x2 = x.multiply(x).mod(p);
        BigInteger v = x2.subtract(_1).multiply(d.multiply(x2).subtract(_1).mod(p).modInverse(p)).mod(p);
        BigInteger y = sqrt(v, p, ybit);
		assert (y != null);
        P[1] = y;
        assert (isPoint(P));
        BigInteger[] Z = mul(P, r);
        assert (Z[0].signum() == 0);
        assert (Z[1].compareTo(_1) == 0);
        return P;
    }

    /**
     * Given a point P = (x, y) on E_521, return its opposite -P = (-x, y).
     *
     * @param   P   a point on E_521.
     * @return  -P
     */
    public static BigInteger[] negate(BigInteger[] P) {
        return new BigInteger[] {P[0].negate().mod(p), P[1]};
    }

    /**
     * Add two given points P1 and P2 on E_521.
     * @param P1
     * @param P2
     * @return
     */
    public static BigInteger[] add(BigInteger[] P1, BigInteger[] P2) {
        assert (isPoint(P1));
        assert (isPoint(P2));
        BigInteger x1 = P1[0], y1 = P1[1];
        BigInteger x2 = P2[0], y2 = P2[1];
        BigInteger x1x2 = x1.multiply(x2).mod(p);
        BigInteger y1y2 = y1.multiply(y2).mod(p);
        // (x1 + y1)*(x2 + y2) - x1*x2 - y1*y2 = x1*y2 + y1*x2
        BigInteger x1y2px2y1 = (x1.add(y1)).multiply(x2.add(y2)).subtract(x1x2).subtract(y1y2).mod(p);
        BigInteger y1y2mx1x2 = y1y2.subtract(x1x2);
        BigInteger dx1x2y1y2 = d.multiply(x1x2).multiply(y1y2).mod(p);
        BigInteger x3 = x1y2px2y1.multiply(_1.add(dx1x2y1y2).modInverse(p)).mod(p);
        BigInteger y3 = y1y2mx1x2.multiply(_1.subtract(dx1x2y1y2).modInverse(p)).mod(p);
        BigInteger[] P3 = new BigInteger[] {x3, y3};
        assert (isPoint(P3));
        return P3;
    }

    public static BigInteger[] mul(BigInteger[] P, BigInteger m) {
        assert (isPoint(P));
        BigInteger[] V = P;
        assert (isPoint(V));
        for (int k = m.bitLength() - 2; k >= 0; k--) {
            V = add(V, V);
            if (m.testBit(k)) {
                V = add(V, P);
            }
        }
        assert (isPoint(V));
        return V;
    }

    /**
     * Find a generator G on E_521.
     *
     * @return G.
     */
    public static BigInteger[] gen() {
        BigInteger x = BigInteger.valueOf(17L), y, x2, v;
        BigInteger[] G = new BigInteger[] {null, null}, Z = null;
        do {
            do {
                x = x.add(_1);
                x2 = x.multiply(x).mod(p);
                v = x2.subtract(_1).multiply(d.multiply(x2).subtract(_1).mod(p).modInverse(p)).mod(p);
                y = sqrt(v, p, false);
            } while (y == null);
            G[0] = x; G[1] = y;
            assert (isPoint(G));
            Z = mul(G, r);
        } while (Z[0].signum() != 0);
        assert (Z[1].compareTo(_1) == 0);
        return G;
    }

    public static String toString(BigInteger[] P) {
        return "(" + P[0] + ", " + P[1] + ")";
    }
}
