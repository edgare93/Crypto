import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class qDSA {
	
	//This one is for the field
	private static BigInteger n = ECC.p;
	
	//This one is for the group 
	private static BigInteger o = ECC.r;
	private static int bl = (n.bitLength() / 8) + 1;
	private static BigInteger[] gen = ECC.gen();
	//fix this later
	private static BigInteger A = ECC.d.add(BigInteger.ONE).multiply(BigInteger.valueOf(2)).multiply(BigInteger.ONE.subtract(ECC.d).modInverse(n)).mod(n);

	private static BigInteger D = A.add(BigInteger.valueOf(2)).multiply(BigInteger.valueOf(4).modInverse(n)); 
	
	public static void main(String[] args){
	
		Random seed = new Random();

		BigInteger a = new BigInteger(256, seed);
		BigInteger A = keygen(a);
		BigInteger b = new BigInteger(256, seed);
		BigInteger B = keygen(b);
		byte[] message = new BigInteger(256, seed).toByteArray();
		BigInteger g = toMont(gen)[0];
		
		BigInteger h = hashH(A,B,message);
		BigInteger s = b.add(h.multiply(a));
		s = s.mod(o);
		
		System.out.println(renesSmith(ML(s,tofraction(g)),ML(h,tofraction(A)),B));
		
		byte[] signed = sign(a,A,message);
		System.out.println(verify(signed,A,message));
		
		
	}
	
	private static BigInteger keygen(BigInteger a)
	{
		BigInteger[] A = ECC.mul(gen,a);
		return toMont(A)[0];
	}
	
	public static byte[] sign(BigInteger z, BigInteger V, byte[] m)
	{
		BigInteger r = new BigInteger(256, new Random());
		BigInteger R = keygen(r);
		
		BigInteger h = hashH(R,V,m);
		
		BigInteger hz = h.multiply(z);
		
		BigInteger s = r.add(hz);
		s = s.mod(o);
		
		byte[] S = s.toByteArray();
		byte[] RR = R.toByteArray();
		
		return concat(S,RR);
		
	}
	
	public static byte[] concat(byte[] a, byte[] b)
	{
		byte[] out = new byte[2*bl];
		for(int i = 0; i < a.length; i++)
		{
			out[i + bl - a.length] = a[i];
		}
		for(int i = 0; i < b.length; i++)
		{
			out[i + bl + bl - b.length] = b[i];
		}
		return out;
	}
	
	public static BigInteger hashH(BigInteger R, BigInteger A, byte[] m){
		byte[] Abytes = A.toByteArray();
		byte[] mA = new byte[m.length + Abytes.length];
		for(int i = 0; i < m.length; i++)
		{
			mA[i] = m[i];
		}
		for(int i = 0; i < Abytes.length; i++)
		{
			mA[i + m.length] = Abytes[i];
		}
		BigInteger h = new BigInteger(SHAKE.KMACXOF256(R.toByteArray(), mA, 256, "H".getBytes()));
		return h.mod(o);
	}
	
	public static boolean verify(byte[] sR, BigInteger V, byte[] message)
	{
		BigInteger s = new BigInteger(Arrays.copyOfRange(sR, 0, bl));
		BigInteger R = new BigInteger(Arrays.copyOfRange(sR, bl, 2*bl));
		
		BigInteger h = hashH(R,V,message);
		BigInteger[] genmont = tofraction(toMont(gen)[0]);
		return renesSmith(ML(s,genmont),ML(h,tofraction(V)),R);
		//return ReneeSmith(tofraction(s.multiply(genmont[0])),tofraction(h.multiply(V)),R);
	}
	
	public static BigInteger defraction(BigInteger[] P)
	{
		return P[0].multiply(P[1].modPow(n.subtract(BigInteger.valueOf(2)),n)).mod(n);
	}
	
	public static BigInteger[] tofraction(BigInteger P)
	{
		return new BigInteger[]{P,BigInteger.ONE};
	}
	
	public static BigInteger[][] MLext(BigInteger k, BigInteger[] P)
	{
		BigInteger[][] R = new BigInteger[][] {P,xDBL(P)};
		boolean swap = false;
		for(int i = k.bitLength()-2; i >=0; i--)
		{
			R = xSWP(R[0],R[1],swap^k.testBit(i));
			R = new BigInteger[][]{xDBL(R[0]),xADD(R[0],R[1],P)};
			
			swap = k.testBit(i);
		}
		R = xSWP(R[0],R[1],swap);
		return R;
	}
	
	public static BigInteger[] ML(BigInteger k, BigInteger[] P)
	{
		BigInteger[][] out = MLext(k,P);
		return out[0];
	}
	
	public static BigInteger[] xDBL(BigInteger[] P)
	{
		BigInteger V1, V2, X2, V3, Z2;
		V1 = P[0].add(P[1]);
		V1 = V1.pow(2).mod(n);
		V2 = P[0].subtract(P[1]);
		V2 = V2.pow(2).mod(n); //Confirm this line
		X2 = V1.multiply(V2);
		V1 = V1.subtract(V2);
		
		V3 = D.multiply(V1);
		V3 = V3.add(V2);
		Z2 = V1.multiply(V3);
		return new BigInteger[] {X2.mod(n),Z2.mod(n)};
	}
	
	public static BigInteger[][] xSWP(BigInteger[] P, BigInteger[] Q, boolean swap)
	{
		BigInteger mask = BigInteger.ZERO;
		if(swap){ mask = BigInteger.valueOf(-1);}
		
		BigInteger Xd = P[0].xor(Q[0]).and(mask);
		BigInteger Zd = P[1].xor(Q[1]).and(mask);
		
		BigInteger[][] out = new BigInteger[2][2];
		out[0][0] = P[0].xor(Xd);
		out[0][1] = P[1].xor(Zd);
		out[1][0] = Q[0].xor(Xd);
		out[1][1] = Q[1].xor(Zd);
		return out;
		
	}
	
	public static BigInteger[] xADD(BigInteger[] P, BigInteger[] Q, BigInteger[] QP)
	{
		BigInteger V0,V1,V2,V3,V4;
		
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
		BigInteger[] out = new BigInteger[]{QP[1].multiply(V3).mod(n),QP[0].multiply(V4).mod(n)};
		return out;
	}
	
	private static BigInteger[] toMont(BigInteger[] in)
	{
		BigInteger[] out = new BigInteger[2];
		BigInteger num = BigInteger.ONE.add(in[1]);
		BigInteger denom = BigInteger.ONE.subtract(in[1]).mod(n);
		out[0] = num.multiply(denom.modInverse(n)).mod(n);
		out[1] = out[0].multiply(in[0].modInverse(n)).mod(n);
		return out;
	}
	
	private static BigInteger[] toEd(BigInteger[] in)
	{
		BigInteger[] out = new BigInteger[2];
		out[0] = in[0].multiply(in[1].modInverse(n)).mod(n);
		BigInteger num = in[0].subtract(BigInteger.ONE).mod(n);
		BigInteger denom = in[0].add(BigInteger.ONE).mod(n);
		out[1] = num.multiply(denom.modInverse(n)).mod(n);
		return out;
	}
	
	private static boolean renesSmith(BigInteger[] P, BigInteger Q[], BigInteger R)
	{
		
		BigInteger Txx = P[0].multiply(Q[0]);
		BigInteger Txz = P[0].multiply(Q[1]);
		BigInteger Tzx = P[1].multiply(Q[0]);
		BigInteger Tzz = P[1].multiply(Q[1]);
		
		BigInteger Bxx = (Txx.subtract(Tzz)).pow(2);
		BigInteger Bzz = (Txz.subtract(Tzx)).pow(2);
		
		BigInteger Bxz = (Txx.add(Tzz).multiply(Txz.add(Tzx))).add(A.multiply(BigInteger.valueOf(2)).multiply(Txx).multiply(Tzz));
		
		BigInteger Xr = R;
		
		BigInteger out = (Bzz.multiply(Xr).subtract(Bxz.multiply(BigInteger.valueOf(2))).multiply(Xr).add(Bxx)).mod(n);
		System.out.println(out);
		return (out.equals(BigInteger.ZERO));
	}
}
