import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class Schnorr {
	
	private static BigInteger n = ECC.p;
	private static BigInteger o = ECC.r;
	private static int bl = (n.bitLength()/8)+1;
	private static BigInteger[] gen = ECC.gen();
	
	
	public static void main(String[] args)
	{
		
		//Hash Function defined by SHAKE
		//KEYGEN
		//Private key s chosen, public key V computed
		//BigInteger s = BigInteger.valueOf(4L);
		//BigInteger s = BigInteger.valueOf(3L);
		Random seed = new Random();
		BigInteger s = new BigInteger(256,seed);

		
		byte[] V = keygen(s);
		//SIGN
		//value r chosen, value R computed
		BigInteger r = new BigInteger(256,seed);
		
		//message is chosen
		byte[] message = {0x04};
		
		
		byte[] test = sign(message, r, s, V);
		System.out.println(verify(message, test, V));
		
	}
	
	public static byte[] keygen(BigInteger s)
	{
		
		BigInteger[] point = ECC.mul(gen, s);
		
		byte[] out = new byte[bl + 1];
		out[0] = (byte) (point[1].testBit(0)?1:0);
		byte[] x = point[0].toByteArray();
		for (int i = 0; i < x.length; i++)
		{
			out[i + bl + 1 - x.length] = x[i];
		}
		return out;
	}
	
	public static BigInteger[] makepoint(byte[] b)
	{
		BigInteger x = new BigInteger(Arrays.copyOfRange(b, 1, b.length));
		boolean y = (b[0]!=0);
		return ECC.makePoint(x,y);
	}
	
	public static BigInteger hashH(byte[] R, byte[] m, byte[] Vi)
	{
		byte[] in = new byte[m.length + Vi.length];
		for(int i = 0; i < m.length; i++)
		{
			in[i] = m[i];
		}
		for(int i = 0; i < Vi.length; i++)
		{
			in[i + m.length] = Vi[i];
		}
		BigInteger h = new BigInteger(SHAKE.KMACXOF256(R, in, 256, "H".getBytes()));
		return h.mod(o);
		
	}
	
	public static byte[] sign(byte[] message, BigInteger r, BigInteger s, byte[] V)
	{
		int ml = message.length;
		//use keygen to create R
		byte[] R = keygen(r);
		// Combine the message and public key into a single byte array
		
		BigInteger h = hashH(R, message, V);
		BigInteger sh = s.multiply(h);
		BigInteger z = sh.add(r);
		z = z.mod(o);
		
		byte[] zp = z.toByteArray();
		
		byte[] out = new byte[(bl + 1) + bl];
		
		for (int i = 0; i < R.length; i++)
		{
			out[i] = R[i];
		}
		for (int i = 0; i < zp.length; i++)
		{
			out[i + bl - zp.length +  bl + 1] = zp[i];
		}
		
		return out;
	}
	
	public static boolean verify(byte[] message, byte[] in, byte[] V)
	{
		int ml = message.length;
		byte[] R = Arrays.copyOfRange(in, 0, bl + 1);
		BigInteger[] Rp = makepoint(R);
		
		byte[] zp = Arrays.copyOfRange(in,bl + 1, in.length);

		BigInteger z = new BigInteger(zp);

		BigInteger[] Vpoint = makepoint(V);
		
		BigInteger h = hashH(R, message, V);
		BigInteger[] zG = ECC.mul(gen, z);
		
		//find the value [h]V
		BigInteger[] hV = ECC.mul(Vpoint, h);
		
		BigInteger[] RR = ECC.add(zG, ECC.negate(hV));
		
		return (RR[0].equals(Rp[0]) && RR[1].equals(Rp[1]));
	}
	
}
