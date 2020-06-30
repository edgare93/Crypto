import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class SEG {

	private static BigInteger n = ECC.p;
	private static BigInteger o = ECC.r;
	private static int bl = (n.bitLength() / 8) + 1;
	private static BigInteger[] gen = ECC.gen();

	public static void main(String[] args) {
		Random seed = new Random();

		BigInteger a = new BigInteger(256, seed);
		byte[] A = keygen(a);

		BigInteger b = new BigInteger(256, seed);
		byte[] B = keygen(b);

		BigInteger c = new BigInteger(256, seed);
		byte[] C = keygen(c);

		byte[] message = new BigInteger(256, seed).toByteArray();
		for(byte x : message)
		{
			System.out.print(x + " ");
		}
		System.out.println();

		byte[] test = signcrypt(B,a,A,message);
		byte[] recieved = decrypt(test,b,B,A);
		
		//byte[] test = broadcastSign(new byte[][] { B, C }, a, A, message);
		//byte[] recieved = broadcastDecrypt(test, b, B, A, 2, 0);
		
		//byte[] test = jointSign(new byte[][] {B,C}, a, A, message);
		//byte[] recieved = jointDecrypt(test, new BigInteger[] {b,c}, A);
		
		System.out.println(verify(recieved,A));
		
		for(int i = 65 + 67; i < recieved.length; i++)
		{
			System.out.print(recieved[i] + " ");
		}
	}
	
	public static boolean verify(byte[] sig, byte[] Va)
	{
		if(sig==null)return false;
		BigInteger z = new BigInteger(Arrays.copyOfRange(sig, 0, 65));
		byte[] R = Arrays.copyOfRange(sig, 65, 65+67);
		BigInteger[] RR = makepoint(R);
		byte[] m = Arrays.copyOfRange(sig, 65 + 67, sig.length);
		
		byte[] mVa = new byte[m.length + Va.length];
		for (int i = 0; i < Va.length; i++) {
			mVa[i] = Va[i];
		}
		for (int i = 0; i < m.length; i++) {
			mVa[i + Va.length] = m[i];
		}
		
		BigInteger h = hashH(R, mVa);
		
		BigInteger[] VaP = makepoint(Va);

		BigInteger[] Vah = ECC.mul(VaP, h);
		BigInteger[] zG = ECC.mul(gen, z);
		BigInteger[] R2 = ECC.add(zG, ECC.negate(Vah));
		return (R2[0].equals(RR[0]) && R2[1].equals(RR[1]));
	}

	public static byte[] keygen(BigInteger s) {

		BigInteger[] point = ECC.mul(gen, s);

		return makeArray(point);
	}
	
	public static byte[] makeArray(BigInteger[] p)
	{
		byte[] out = new byte[bl + 1];
		out[0] = (byte) (p[1].testBit(0) ? 1 : 0);
		byte[] x = p[0].toByteArray();
		for (int i = 0; i < x.length; i++) {
			out[i + bl + 1 - x.length] = x[i];
		}
		return out;
	}

	public static BigInteger[] makepoint(byte[] b) {
		BigInteger x = new BigInteger(Arrays.copyOfRange(b, 1, b.length));
		boolean y = (b[0] != 0);
		return ECC.makePoint(x, y);
	}

	public static BigInteger hashH(byte[] R, byte[] mVa) {
		BigInteger h = new BigInteger(SHAKE.KMACXOF256(R, mVa, 512, "H".getBytes()));
		return h.mod(o);

	}

	public static byte[] hashF(BigInteger z) {
		return SHAKE.KMACXOF256(new byte[0], z.toByteArray(), 1024, "F".getBytes());
	}

	public static BigInteger hashG(byte[] R, byte[] Vb, BigInteger[] omega) {
		byte[] ob = omega[0].toByteArray();
		byte[] m2 = new byte[ob.length + Vb.length];
		for (int i = 0; i < ob.length; i++) {
			m2[i] = ob[i];
		}
		for (int i = 0; i < Vb.length; i++) {
			m2[i + ob.length] = Vb[i];
		}

		return new BigInteger(SHAKE.KMACXOF256(R, m2, 512, "G".getBytes()));
	}

	public static byte[] signcrypt(byte[] Vb, BigInteger sa, byte[] Va, byte[] message) {
		int ml = message.length;
		
		BigInteger r = new BigInteger(256, new Random());

		// compute R
		byte[] R = keygen(r);

		byte[] mVa = new byte[ml + Va.length];
		for (int i = 0; i < Va.length; i++) {
			mVa[i] = Va[i];
		}
		for (int i = 0; i < ml; i++) {
			mVa[i + Va.length] = message[i];
		}

		// compute h in Z/n
		BigInteger h = hashH(R, mVa);
		BigInteger sh = sa.multiply(h);
		sh = sh.mod(o);
		BigInteger z = sh.add(r);
		z = z.mod(o);
		BigInteger[] Vbp = makepoint(Vb);
		BigInteger[] omega = ECC.mul(Vbp, r);

		BigInteger temp = hashG(R, Vb, omega);

		BigInteger zz = z.xor(temp);

		byte[] zeta = zz.toByteArray();

		byte[] hash = hashF(z);

		for (int i = 0; i < mVa.length; i++) {
			mVa[i] = (byte) (mVa[i] ^ hash[i]);
		}
		byte[] out = new byte[65 + 67 + mVa.length];

		// if Zeta is negative and shorter than 65 bytes it needs to have
		// leading 1's in the output array so that it can be read back in
		// correctly
		if (zz.signum() == -1) {
			for (int i = 0; i < (65 - zeta.length); i++) {
				out[i] = -1;
			}
		}

		for (int i = 0; i < zeta.length; i++) {
			out[i + 65 - zeta.length] = zeta[i];
		}
		for (int i = 0; i < 67; i++) {
			out[i + 65] = R[i];
		}
		for (int i = 0; i < mVa.length; i++) {
			out[i + 65 + 67] = mVa[i];
		}

		return out;
	}

	public static byte[] broadcastSign(byte[][] Vi, BigInteger sa, byte[] Va, byte[] message) {
		int ml = message.length;
		// DO NOT LEAVE THIS AS IS, THIS IS PROOF OF CONCEPT
		// choose r in Z/n

		BigInteger r = new BigInteger(256, new Random());

		// compute R
		byte[] R = keygen(r);

		byte[] mVa = new byte[ml + Va.length];
		for (int i = 0; i < Va.length; i++) {
			mVa[i] = Va[i];
		}
		for (int i = 0; i < ml; i++) {
			mVa[i + Va.length] = message[i];
		}

		// compute h in Z/n
		BigInteger h = hashH(R, mVa);
		BigInteger sh = sa.multiply(h);
		sh = sh.mod(o);
		BigInteger z = sh.add(r);
		z = z.mod(o);
		byte[] hash = hashF(z);
		
		for (int i = 0; i < mVa.length; i++) {
			mVa[i] = (byte) (mVa[i] ^ hash[i]);
		}
		byte[] out = new byte[65 * Vi.length + 67 + mVa.length];

		for (int j = 0; j < Vi.length; j++) {
			BigInteger[] Vbp = makepoint(Vi[j]);
			BigInteger[] omega = ECC.mul(Vbp, r);

			BigInteger temp = hashG(R, Vi[j], omega);

			BigInteger zz = z.xor(temp);
			

			byte[] zeta = zz.toByteArray();

			

			// if Zeta is negative and shorter than 65 bytes it needs to have
			// leading 1's in the output array so that it can be read back in
			// correctly
			if (zz.signum() == -1) {
				for (int i = 0; i < (65 - zeta.length); i++) {
					out[i + 65 * j] = -1;
				}
			}

			for (int i = 0; i < zeta.length; i++) {
				out[i + 65 * j + 65 - zeta.length] = zeta[i];
			}
		}

		for (int i = 0; i < 67; i++) {
			out[i + 65 * Vi.length] = R[i];
		}
		for (int i = 0; i < mVa.length; i++) {
			out[i + 65 * Vi.length + 67] = mVa[i];
		}

		return out;
	}
	
	public static byte[] jointSign(byte[][] Vi, BigInteger sa, byte[] Va, byte[] message)
	{
		int ml = message.length;

		BigInteger r = new BigInteger(256, new Random());

		// compute R
		byte[] R = keygen(r);
		
		BigInteger[] V = makepoint(Vi[0]);
		for(int i = 1; i < Vi.length; i++)
		{
			BigInteger[] temp = makepoint(Vi[i]);
			V = ECC.add(V, temp);
		}
		
		BigInteger[] omega = ECC.mul(V, r);
		
		byte[] mVa = new byte[ml + Va.length];
		for (int i = 0; i < Va.length; i++) {
			mVa[i] = Va[i];
		}
		for (int i = 0; i < ml; i++) {
			mVa[i + Va.length] = message[i];
		}

		// compute h in Z/n
		BigInteger h = hashH(R, mVa);
		BigInteger sh = sa.multiply(h);
		sh = sh.mod(o);
		BigInteger z = sh.add(r);
		z = z.mod(o);

		BigInteger temp = hashG(R, makeArray(V), omega);

		BigInteger zz = z.xor(temp);

		byte[] zeta = zz.toByteArray();

		byte[] hash = hashF(z);

		for (int i = 0; i < mVa.length; i++) {
			mVa[i] = (byte) (mVa[i] ^ hash[i]);
		}
		byte[] out = new byte[65 + 67 + mVa.length];

		// if Zeta is negative and shorter than 65 bytes it needs to have
		// leading 1's in the output array so that it can be read back in
		// correctly
		if (zz.signum() == -1) {
			for (int i = 0; i < (65 - zeta.length); i++) {
				out[i] = -1;
			}
		}

		for (int i = 0; i < zeta.length; i++) {
			out[i + 65 - zeta.length] = zeta[i];
		}
		for (int i = 0; i < 67; i++) {
			out[i + 65] = R[i];
		}
		for (int i = 0; i < mVa.length; i++) {
			out[i + 65 + 67] = mVa[i];
		}

		return out;
		
	}

	public static byte[] jointDecrypt(byte[] C, BigInteger[] si, byte[] Va)
	{
		BigInteger zeta = new BigInteger(Arrays.copyOfRange(C, 0, 65));
		byte[] R = Arrays.copyOfRange(C, 65, 65 + 67);
		BigInteger[] RR = makepoint(R);
		byte[] mVa = Arrays.copyOfRange(C, 65 + 67, C.length);
		
		//IN AN ACTUAL IMPLEMENTATION THESE STEPS WOULD BE DONE BY THE KEY HOLDERS INDEPENDANTLY TO PRESERVE THE SECRECY OF THEIR KEYS
		//THE ONLY REASON I'M DOING IT HERE IS TO STREAMLINE IT WHILE I'M FIXING BUGS
		
		BigInteger[] omega = ECC.mul(RR, si[0]);
		BigInteger[] V = ECC.mul(gen, si[0]);
		
		for (int i = 1; i < si.length; i++)
		{
			omega = ECC.add(omega, ECC.mul(RR, si[i]));
			V = ECC.add(V, ECC.mul(gen, si[i]));
		}

		BigInteger temp = hashG(R, makeArray(V), omega);

		BigInteger z = zeta.xor(temp);
		
		// rejects if z isn't in Z/n
		if(z.equals(BigInteger.ZERO) || z.compareTo(o)>=0) return null;
		

		byte[] hash = hashF(z);

		for (int i = 0; i < mVa.length; i++) {
			mVa[i] = (byte) (mVa[i] ^ hash[i]);
		}
		byte[] m = Arrays.copyOfRange(mVa, 67, mVa.length);
		byte[] Vaa = Arrays.copyOfRange(mVa, 0, 67);
		
		if(!Arrays.equals(Va, Vaa))return null;

		BigInteger h = hashH(R, mVa);

		BigInteger[] VaP = makepoint(Va);

		BigInteger[] Vah = ECC.mul(VaP, h);
		BigInteger[] zG = ECC.mul(gen, z);
		BigInteger[] R2 = ECC.add(zG, ECC.negate(Vah));
		if (R2[0].equals(RR[0]) && R2[1].equals(RR[1]))
			return m;
		else
			return null;
	}
	
	public static byte[] broadcastDecrypt(byte[] C, BigInteger sb, byte[] Vb, byte[] Va, int total, int target) {
		byte[] zz = Arrays.copyOfRange(C, 65 * target, 65 * (target + 1));
		BigInteger zeta = new BigInteger(zz);

		byte[] R = Arrays.copyOfRange(C, 65 * total, 65 * total + 67);

		BigInteger[] RR = makepoint(R);
		byte[] mu = Arrays.copyOfRange(C, 65 * total + 67, C.length);

		BigInteger[] omega = ECC.mul(RR, sb);

		BigInteger temp = hashG(R, Vb, omega);

		BigInteger z = zeta.xor(temp);
		if(z.equals(BigInteger.ZERO) || z.compareTo(o)>=0) return null;
		

		byte[] hash = hashF(z);
				
		for (int i = 0; i < mu.length; i++) {
			mu[i] = (byte) (mu[i] ^ hash[i]);
		}
		
		
		byte[] m = Arrays.copyOfRange(mu, 67, mu.length);
		byte[] Vaa = Arrays.copyOfRange(mu, 0, 67);
		
		if(!Arrays.equals(Vaa, Va)) return null;
		

		
		BigInteger h = hashH(R, mu);
		BigInteger[] VaP = makepoint(Va);

		BigInteger[] Vah = ECC.mul(VaP, h);
		BigInteger[] zG = ECC.mul(gen, z);
		BigInteger[] R2 = ECC.add(zG, ECC.negate(Vah));
		if (R2[0].equals(RR[0]) && R2[1].equals(RR[1]))
			{
			//create and output the signature
			byte[] out = new byte[65 + 67 + m.length];
			byte[] zbyte = z.toByteArray();
			for(int i = 0; i < zbyte.length; i++)
			{
				out[i + 65 - zbyte.length] = zz[i];
			}
			for(int i = 0; i < R.length; i++)
			{
				out[i + 65 + 67 - R.length] = R[i];
			}
			for(int i = 0; i < m.length; i++)
			{
				out[i + 65 + 67] = m[i];
			}
			return out;
			}
		else
			return null;
	}

	public static byte[] decrypt(byte[] C, BigInteger sb, byte[] Vb, byte[] Va) {
		BigInteger zeta = new BigInteger(Arrays.copyOfRange(C, 0, 65));
		byte[] R = Arrays.copyOfRange(C, 65, 65 + 67);
		BigInteger[] RR = makepoint(R);
		byte[] mVa = Arrays.copyOfRange(C, 65 + 67, C.length);

		BigInteger[] omega = ECC.mul(RR, sb);

		BigInteger temp = hashG(R, Vb, omega);

		BigInteger z = zeta.xor(temp);
		
		//rejects if z is not in Z/n
		if(z.equals(BigInteger.ZERO) || z.compareTo(o)>=0) return null;
		
		byte[] hash = hashF(z);

		for (int i = 0; i < mVa.length; i++) {
			mVa[i] = (byte) (mVa[i] ^ hash[i]);
		}
		byte[] m = Arrays.copyOfRange(mVa, 67, mVa.length);
		byte[] Vaa = Arrays.copyOfRange(mVa, 0, 67);
		
		
		if(!Arrays.equals(Va, Vaa))return null;

		BigInteger h = hashH(R, mVa);

		BigInteger[] VaP = makepoint(Va);

		BigInteger[] Vah = ECC.mul(VaP, h);
		BigInteger[] zG = ECC.mul(gen, z);
		BigInteger[] R2 = ECC.add(zG, ECC.negate(Vah));
		if (R2[0].equals(RR[0]) && R2[1].equals(RR[1]))
		{
			//create and output the signature
			byte[] out = new byte[65 + 67 + m.length];
			byte[] zz = z.toByteArray();
			for(int i = 0; i < zz.length; i++)
			{
				out[i + 65 - zz.length] = zz[i];
			}
			for(int i = 0; i < R.length; i++)
			{
				out[i + 65 + 67 - R.length] = R[i];
			}
			for(int i = 0; i < m.length; i++)
			{
				out[i + 65 + 67] = m[i];
			}
			return out;
		}
		else
			return null;
	}
}
