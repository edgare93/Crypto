import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class HybridSigncrypt {

	// This one is for the field
	private static BigInteger n = ECC.p;
	// This one is for the group
	private static BigInteger o = ECC.r;

	private static int bl = (n.bitLength() / 8) + 1;

	private static BigInteger gen = toMont(ECC.gen())[0];

	private static BigInteger A = ECC.d.add(BigInteger.ONE).multiply(BigInteger.valueOf(2))
			.multiply(BigInteger.ONE.subtract(ECC.d).modInverse(n)).mod(n);

	private static BigInteger D = A.add(BigInteger.valueOf(2)).multiply(BigInteger.valueOf(4).modInverse(n));

	public static void main(String[] args) {
		Random seed = new Random();

		BigInteger a = new BigInteger(256, seed);
		BigInteger A = keygen(a);
		BigInteger b = new BigInteger(256, seed);
		BigInteger B = keygen(b);
		BigInteger c = new BigInteger(256, seed);
		BigInteger C = keygen(c);
		
		//The message length is limited by the output of HashF, which can be made larger if larger messages need to be sent regularly.
		byte[] message = new BigInteger(256, seed).toByteArray();

		for (byte x : message) {
			System.out.print(x + " ");
		}
		System.out.println();

		byte[] crypt = signcrypt(B,a,A,message);
		byte[] recieved = decrypt(crypt,b,B,C);

		//byte[] crypt = broadcastSigncrypt(new BigInteger[] { B, C }, a, A, message);
		//byte[] recieved = broadcastDecrypt(crypt, c, C, A, 2, 1);
		System.out.println(verify(recieved,A));

		for (int i = 65 + 66; i < recieved.length; i++) {
			System.out.print(recieved[i] + " ");
		}
	}

	public static byte[] broadcastSigncrypt(BigInteger[] Bi, BigInteger a, BigInteger A, byte[] message) {
		int ml = message.length;

		BigInteger r = new BigInteger(256, new Random());
		byte[] R = keygen(r).toByteArray();

		byte[] AA = A.toByteArray();
		byte[] mA = new byte[ml + bl];
		for (int i = 0; i < AA.length; i++) {
			mA[i + bl - AA.length] = AA[i];
		}
		for (int i = 0; i < ml; i++) {
			mA[i + bl] = message[i];
		}

		BigInteger h = hashH(R, mA);
		BigInteger ah = a.multiply(h);
		BigInteger z = ah.add(r);
		z = z.mod(o);

		byte[] out = new byte[65 * Bi.length + 66 + mA.length];

		byte[] hash = hashF(z);
		for (int i = 0; i < mA.length; i++) {
			mA[i] = (byte) (mA[i] ^ hash[i]);
		}
		for (int j = 0; j < Bi.length; j++) {

			BigInteger omega = defraction(ML(r, tofraction(Bi[j])));
			BigInteger temp = hashG(R, Bi[j], omega);
			BigInteger zz = z.xor(temp);
			byte[] zeta = zz.toByteArray();

			if (zz.signum() == -1) {
				for (int i = 0; i < (65 - zeta.length); i++) {
					out[i + 65 * j] = -1;
				}
			}

			for (int i = 0; i < zeta.length; i++) {
				out[i + 65 * j + 65 - zeta.length] = zeta[i];
			}
		}
		for (int i = 0; i < R.length; i++) {
			out[i + 65 * Bi.length + 66 - R.length] = R[i];
		}
		for (int i = 0; i < mA.length; i++) {
			out[i + 65 * Bi.length + 66] = mA[i];
		}
		return out;
	}

	public static byte[] broadcastDecrypt(byte[] C, BigInteger b, BigInteger B, BigInteger A, int total, int target) {
		BigInteger zeta = new BigInteger(Arrays.copyOfRange(C, 65 * target, 65 * (target + 1)));
		BigInteger R = new BigInteger(Arrays.copyOfRange(C, 65 * total, 65 * total + 66));
		byte[] RR = R.toByteArray();
		byte[] mu = Arrays.copyOfRange(C, 65 * total + 66, C.length);

		BigInteger omega = defraction(ML(b, tofraction(R)));
		BigInteger temp = hashG(RR, B, omega);
		BigInteger z = zeta.xor(temp);
		
		// rejects if z isn't in Z/n
		if(z.equals(BigInteger.ZERO) || z.compareTo(o)>=0) return null;
		

		byte[] hash = hashF(z);
		for (int i = 0; i < mu.length; i++) {
			mu[i] = (byte) (mu[i] ^ hash[i]);
		}
		byte[] m = Arrays.copyOfRange(mu, 66, mu.length);
		BigInteger AA = new BigInteger(Arrays.copyOfRange(mu, 0, 66));

		if (!AA.equals(A))
			return null;

		BigInteger h = hashH(RR, mu);

		if (renesSmith(ML(z, tofraction(gen)), ML(h, tofraction(A)), R)) {
			//create and output the signature
			byte[] out = new byte[65 + 66 + m.length];
			byte[] zz = z.toByteArray();
			for(int i = 0; i < zz.length; i++)
			{
				out[i + 65 - zz.length] = zz[i];
			}
			for(int i = 0; i < RR.length; i++)
			{
				out[i + 65 + 66 - RR.length] = RR[i];
			}
			for(int i = 0; i < m.length; i++)
			{
				out[i + 65 + 66] = m[i];
			}
			return out;
		} else {
			return null;
		}

	}
	
	public static boolean verify(byte[] sig, BigInteger A)
	{
		if(sig==null)return false;
		BigInteger z = new BigInteger(Arrays.copyOfRange(sig, 0, 65));
		BigInteger R = new BigInteger(Arrays.copyOfRange(sig, 65, 65+66));
		byte[] m = Arrays.copyOfRange(sig, 65+66, sig.length);
		byte[] AA = A.toByteArray();
		
		byte[] mA = new byte[m.length + bl];
		for (int i = 0; i < AA.length; i++) {
			mA[i + bl - AA.length] = AA[i];
		}
		for (int i = 0; i < m.length; i++) {
			mA[i + bl] = m[i];
		}
		
		BigInteger h = hashH(R.toByteArray(),mA);
		return (renesSmith(ML(z, tofraction(gen)), ML(h, tofraction(A)), R));
	}
	
	/*
	public static byte[] jointSigncrypt(BigInteger[] Bi, BigInteger a, byte[] message) {

		BigInteger B = Bi[0];
		for (BigInteger b : Bi) {
			// THIS MAY PRESENT A PROBLEM
			B = xADD();
		}
		B = B.mod(n);

		int ml = message.length;

		BigInteger r = new BigInteger(256, new Random());
		byte[] R = keygen(r).toByteArray();

		// This will be more efficient to remove and add another input but I'm
		// leaving it in for right now
		BigInteger A = keygen(a);
		byte[] AA = A.toByteArray();
		byte[] mA = new byte[ml + bl];
		for (int i = 0; i < AA.length; i++) {
			mA[i + bl - AA.length] = AA[i];
		}
		for (int i = 0; i < ml; i++) {
			mA[i + bl] = message[i];
		}

		BigInteger h = hashH(R, mA);
		BigInteger ah = a.multiply(h);
		BigInteger z = ah.add(r);
		z = z.mod(o);

		BigInteger omega = defraction(ML(r, tofraction(B)));
		BigInteger temp = hashG(R, B, omega);
		BigInteger zz = z.xor(temp);
		byte[] zeta = zz.toByteArray();

		byte[] hash = hashF(z);

		for (int i = 0; i < mA.length; i++) {
			mA[i] = (byte) (mA[i] ^ hash[i]);
		}

		byte[] out = new byte[65 + 66 + mA.length];

		if (zz.signum() == -1) {
			for (int i = 0; i < (65 - zeta.length); i++) {
				out[i] = -1;
			}
		}

		for (int i = 0; i < zeta.length; i++) {
			out[i + 65 - zeta.length] = zeta[i];
		}
		for (int i = 0; i < R.length; i++) {
			out[i + 65 + 66 - R.length] = R[i];
		}
		for (int i = 0; i < mA.length; i++) {
			out[i + 65 + 66] = mA[i];
		}

		return out;
	}
	
	*/
	
	/*
	
	public static byte[] jointDecrypt(byte[] C, BigInteger[] B, BigInteger[] omega) {
		BigInteger zeta = new BigInteger(Arrays.copyOfRange(C, 0, 65));
		BigInteger R = new BigInteger(Arrays.copyOfRange(C, 65, 65 + 66));
		byte[] RR = R.toByteArray();
		byte[] mu = Arrays.copyOfRange(C, 65 + 66, C.length);

		// Once again, I might decide to remove this step in favor of a
		// secondary input to help performance
		BigInteger B = keygen(b);

		// THIS STEP MAY BE A PROBLEM SINCE SUMMING THE KEYS MAY NOT BE POSSIBLE
		BigInteger omega = defraction(ML(b, tofraction(R)));
		BigInteger temp = hashG(RR, B, omega);
		BigInteger z = zeta.xor(temp);
		// rejects if z isn't in Z/n

		byte[] hash = hashF(z);
		for (int i = 0; i < mu.length; i++) {
			mu[i] = (byte) (mu[i] ^ hash[i]);
		}
		byte[] m = Arrays.copyOfRange(mu, 66, mu.length);
		BigInteger AA = new BigInteger(Arrays.copyOfRange(mu, 0, 66));

		if (!AA.equals(A))
			return null;

		BigInteger h = hashH(RR, mu);

		if (renesSmith(ML(z, tofraction(gen)), ML(h, tofraction(A)), R)) {
			return m;
		} else {
			return null;
		}

	}
	
	*/
	
	public static byte[] signcrypt(BigInteger B, BigInteger a, BigInteger A, byte[] message) {
		int ml = message.length;

		BigInteger r = new BigInteger(256, new Random());
		byte[] R = keygen(r).toByteArray();

		byte[] AA = A.toByteArray();
		byte[] mA = new byte[ml + bl];
		for (int i = 0; i < AA.length; i++) {
			mA[i + bl - AA.length] = AA[i];
		}
		for (int i = 0; i < ml; i++) {
			mA[i + bl] = message[i];
		}

		BigInteger h = hashH(R, mA);
		BigInteger ah = a.multiply(h);
		BigInteger z = ah.add(r);
		z = z.mod(o);

		BigInteger omega = defraction(ML(r, tofraction(B)));
		BigInteger temp = hashG(R, B, omega);
		BigInteger zz = z.xor(temp);
		byte[] zeta = zz.toByteArray();

		byte[] hash = hashF(z);
		
		for (int i = 0; i < mA.length; i++) {
			mA[i] = (byte) (mA[i] ^ hash[i]);
		}

		byte[] out = new byte[65 + 66 + mA.length];

		if (zz.signum() == -1) {
			for (int i = 0; i < (65 - zeta.length); i++) {
				out[i] = -1;
			}
		}

		for (int i = 0; i < zeta.length; i++) {
			out[i + 65 - zeta.length] = zeta[i];
		}
		for (int i = 0; i < R.length; i++) {
			out[i + 65 + 66 - R.length] = R[i];
		}
		for (int i = 0; i < mA.length; i++) {
			out[i + 65 + 66] = mA[i];
		}

		return out;
	}
	
	public static byte[] decrypt(byte[] C, BigInteger b, BigInteger B, BigInteger A) {
		BigInteger zeta = new BigInteger(Arrays.copyOfRange(C, 0, 65));
		BigInteger R = new BigInteger(Arrays.copyOfRange(C, 65, 65 + 66));
		byte[] RR = R.toByteArray();
		byte[] mu = Arrays.copyOfRange(C, 65 + 66, C.length);

		BigInteger omega = defraction(ML(b, tofraction(R)));
		BigInteger temp = hashG(RR, B, omega);
		BigInteger z = zeta.xor(temp);
		
		// rejects if z isn't in Z/n
		if(z.equals(BigInteger.ZERO) || z.compareTo(o)>=0) return null;
		

		byte[] hash = hashF(z);
		for (int i = 0; i < mu.length; i++) {
			mu[i] = (byte) (mu[i] ^ hash[i]);
		}
		byte[] m = Arrays.copyOfRange(mu, 66, mu.length);
		BigInteger AA = new BigInteger(Arrays.copyOfRange(mu, 0, 66));

		if (!AA.equals(A))
			return null;

		BigInteger h = hashH(RR, mu);

		if (renesSmith(ML(z, tofraction(gen)), ML(h, tofraction(A)), R)) {
			//create and output the signature
			byte[] out = new byte[65 + 66 + m.length];
			byte[] zz = z.toByteArray();
			for(int i = 0; i < zz.length; i++)
			{
				out[i + 65 - zz.length] = zz[i];
			}
			for(int i = 0; i < RR.length; i++)
			{
				out[i + 65 + 66 - RR.length] = RR[i];
			}
			for(int i = 0; i < m.length; i++)
			{
				out[i + 65 + 66] = m[i];
			}
			return out;
		} else {
			return null;
		}
	}

	public static BigInteger hashH(byte[] R, byte[] mVa) {
		BigInteger h = new BigInteger(SHAKE.KMACXOF256(R, mVa, 512, "H".getBytes()));
		return h.mod(o);

	}

	public static BigInteger hashG(byte[] R, BigInteger B, BigInteger omega) {
		byte[] ob = omega.toByteArray();
		byte[] BB = B.toByteArray();

		byte[] m2 = new byte[ob.length + BB.length];
		for (int i = 0; i < ob.length; i++) {
			m2[i] = ob[i];
		}
		for (int i = 0; i < BB.length; i++) {
			m2[i + ob.length] = BB[i];
		}

		return new BigInteger(SHAKE.KMACXOF256(R, m2, 512, "G".getBytes()));
	}

	public static byte[] hashF(BigInteger z) {
		return SHAKE.KMACXOF256(new byte[0], z.toByteArray(), 1024, "F".getBytes());
	}

	public static BigInteger keygen(BigInteger a) {
		return defraction(ML(a, tofraction(gen)));
	}

	public static BigInteger defraction(BigInteger[] P) {
		return P[0].multiply(P[1].modPow(n.subtract(BigInteger.valueOf(2)), n)).mod(n);
	}

	public static BigInteger[] tofraction(BigInteger P) {
		return new BigInteger[] { P, BigInteger.ONE };
	}

	private static BigInteger[] toMont(BigInteger[] in) {
		BigInteger[] out = new BigInteger[2];
		BigInteger num = BigInteger.ONE.add(in[1]);
		BigInteger denom = BigInteger.ONE.subtract(in[1]).mod(n);
		out[0] = num.multiply(denom.modInverse(n)).mod(n);
		out[1] = out[0].multiply(in[0].modInverse(n)).mod(n);
		return out;
	}

	private static BigInteger[][] MLext(BigInteger k, BigInteger[] P) {
		BigInteger[][] R = new BigInteger[][] { P, xDBL(P) };
		boolean swap = false;
		for (int i = k.bitLength() - 2; i >= 0; i--) {
			R = xSWP(R[0], R[1], swap ^ k.testBit(i));
			R = new BigInteger[][] { xDBL(R[0]), xADD(R[0], R[1], P) };

			swap = k.testBit(i);
		}
		R = xSWP(R[0], R[1], swap);
		return R;
	}

	private static BigInteger[] ML(BigInteger k, BigInteger[] P) {
		BigInteger[][] out = MLext(k, P);
		return out[0];
	}

	private static BigInteger[] xDBL(BigInteger[] P) {
		BigInteger V1, V2, X2, V3, Z2;
		V1 = P[0].add(P[1]);
		V1 = V1.pow(2).mod(n);
		V2 = P[0].subtract(P[1]);
		V2 = V2.pow(2).mod(n); // Confirm this line
		X2 = V1.multiply(V2);
		V1 = V1.subtract(V2);

		V3 = D.multiply(V1);
		V3 = V3.add(V2);
		Z2 = V1.multiply(V3);
		return new BigInteger[] { X2.mod(n), Z2.mod(n) };
	}

	private static BigInteger[][] xSWP(BigInteger[] P, BigInteger[] Q, boolean swap) {
		BigInteger mask = BigInteger.ZERO;
		if (swap) {
			mask = BigInteger.valueOf(-1);
		}

		BigInteger Xd = P[0].xor(Q[0]).and(mask);
		BigInteger Zd = P[1].xor(Q[1]).and(mask);

		BigInteger[][] out = new BigInteger[2][2];
		out[0][0] = P[0].xor(Xd);
		out[0][1] = P[1].xor(Zd);
		out[1][0] = Q[0].xor(Xd);
		out[1][1] = Q[1].xor(Zd);
		return out;

	}

	private static BigInteger[] xADD(BigInteger[] P, BigInteger[] Q, BigInteger[] QP) {
		BigInteger V0, V1, V2, V3, V4;

		V0 = P[0].add(P[1]);
		V1 = Q[0].subtract(Q[1]);
		V1 = V1.multiply(V0);
		V0 = P[0].subtract(P[1]);
		V2 = Q[0].add(Q[1]);
		V2 = V2.multiply(V0);
		V3 = V1.add(V2);
		V3 = V3.pow(2);
		V4 = V1.subtract(V2);
		V4 = V4.pow(2);
		BigInteger[] out = new BigInteger[] { QP[1].multiply(V3).mod(n), QP[0].multiply(V4).mod(n) };
		return out;
	}

	private static boolean renesSmith(BigInteger[] P, BigInteger Q[], BigInteger R) {

		BigInteger Txx = P[0].multiply(Q[0]);
		BigInteger Txz = P[0].multiply(Q[1]);
		BigInteger Tzx = P[1].multiply(Q[0]);
		BigInteger Tzz = P[1].multiply(Q[1]);

		BigInteger Bxx = (Txx.subtract(Tzz)).pow(2);
		BigInteger Bzz = (Txz.subtract(Tzx)).pow(2);

		BigInteger Bxz = (Txx.add(Tzz).multiply(Txz.add(Tzx)))
				.add(A.multiply(BigInteger.valueOf(2)).multiply(Txx).multiply(Tzz));

		BigInteger Xr = R;

		BigInteger out = (Bzz.multiply(Xr).subtract(Bxz.multiply(BigInteger.valueOf(2))).multiply(Xr).add(Bxx)).mod(n);
		return (out.equals(BigInteger.ZERO));
	}

	
	
}