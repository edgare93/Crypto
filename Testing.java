import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class Testing {

	public static void main(String[] args)
	{
		int trials = 100;
		int mlength = 512;
		System.out.println("Plaintext length is " + mlength + " bits");

		Random seed = new Random();
		BigInteger[] s = new BigInteger[trials];
		BigInteger[] Vh = new BigInteger[trials];
		byte[][] Vs = new byte[trials][];

		byte[][] segEncrypt = new byte[trials][];
		byte[][] segDecrypt = new byte[trials][];
		byte[][] hybridEncrypt = new byte[trials][];
		byte[][] hybridDecrypt = new byte[trials][];



		byte[] message = new BigInteger(256,seed).toByteArray();

		for (int i = 0; i < trials; i++)s[i] = new BigInteger(256,seed);

		//Checks the time taken to generate keys for SEG
		long begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			Vs[i] = SEG.keygen(s[i]);
		}
		long end = System.currentTimeMillis();
		System.out.println("Generating " + trials + " keys for SEG took " + (end - begin) + " milliseconds");

		//Checks the time taken to encrypt using SEG
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			segEncrypt[i] = SEG.signcrypt(Vs[(i+1)%trials], s[i], Vs[i], message);
		}
		end = System.currentTimeMillis();
		System.out.println("Encrypting " + trials + " times with SEG took " + (end - begin) + " milliseconds");

		//Checks the time taken to decrypt using SEG
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			segDecrypt[i] = SEG.decrypt(segEncrypt[i], s[i], Vs[i], Vs[i]);
		}
		end = System.currentTimeMillis();
		System.out.println("Decrypting " + trials + " times with SEG took " + (end - begin) + " milliseconds");

		boolean correct = true;
		//Checks the time taken to decrypt using SEG
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			correct = correct && SEG.verify(segDecrypt[i], Vs[i]);
		}
		end = System.currentTimeMillis();
		System.out.println("Verifying " + trials + " times with SEG took " + (end - begin) + " milliseconds and was " + correct);

		//Checks the time taken to generate the keys for the Hybrid Scheme
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			Vh[i] = HybridSigncrypt.keygen(s[i]);
		}
		end = System.currentTimeMillis();
		System.out.println("Generating " + trials + " keys for the Hybrid scheme took " + (end - begin) + " milliseconds");

		//Checks the time taken to encrypt using the Hybrid Scheme
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			hybridEncrypt[i] = HybridSigncrypt.signcrypt(Vh[(i+1)%trials], s[i], Vh[i], message);
		}
		end = System.currentTimeMillis();
		System.out.println("Encrypting " + trials + " times with the Hybrid scheme took " + (end - begin) + " milliseconds");

		//Checks the time taken to decrypt using the Hybrid Scheme
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			hybridDecrypt[i] = HybridSigncrypt.decrypt(hybridEncrypt[i], s[i], Vh[i], Vh[i]);
		}
		end = System.currentTimeMillis();
		System.out.println("Decrypting " + trials + " times with the Hybrid scheme took " + (end - begin) + " milliseconds");

		correct = true;
		//Checks the time taken to decrypt using SEG
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			correct = correct && HybridSigncrypt.verify(hybridDecrypt[i], Vh[i]);
		}
		end = System.currentTimeMillis();
		System.out.println("Verifying " + trials + " times with the Hybrid Scheme took " + (end - begin) + " milliseconds and was " + correct);

		
		
		byte[][] segBroad2 = Arrays.copyOf(Vs, 2);
		BigInteger[] hybBroad2 = Arrays.copyOf(Vh, 2);

		segEncrypt = new byte[trials][];
		segDecrypt = new byte[trials][];
		hybridEncrypt = new byte[trials][];
		hybridDecrypt = new byte[trials][];

		//Checks the time taken to broadcast encrypt using SEG
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			segEncrypt[i] = SEG.broadcastSign(segBroad2, s[i], Vs[i], message);
		}
		end = System.currentTimeMillis();
		System.out.println("Encrypting for two recipients " + trials + " times with SEG took " + (end - begin) + " milliseconds");

		//Checks the time taken to broadcast encrypt using the hybrid scheme
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			hybridEncrypt[i] = HybridSigncrypt.broadcastSigncrypt(hybBroad2, s[i], Vh[i], message);
		}
		end = System.currentTimeMillis();
		System.out.println("Encrypting for two recipients " + trials + " times with the hybrid scheme took " + (end - begin) + " milliseconds");

		byte[][] segBroad10 = Arrays.copyOf(Vs, 10);
		BigInteger[] hybBroad10 = Arrays.copyOf(Vh, 10);

		segEncrypt = new byte[trials][];
		segDecrypt = new byte[trials][];
		hybridEncrypt = new byte[trials][];
		hybridDecrypt = new byte[trials][];

		//Checks the time taken to broadcast encrypt using SEG
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			segEncrypt[i] = SEG.broadcastSign(segBroad10, s[i], Vs[i], message);
		}
		end = System.currentTimeMillis();
		System.out.println("Encrypting for ten recipients " + trials + " times with SEG took " + (end - begin) + " milliseconds");

		//Checks the time taken to broadcast encrypt using the hybrid scheme
		begin = System.currentTimeMillis();
		for (int i = 0; i < trials; i++)
		{
			hybridEncrypt[i] = HybridSigncrypt.broadcastSigncrypt(hybBroad10, s[i], Vh[i], message);
		}
		end = System.currentTimeMillis();
		System.out.println("Encrypting for ten recipients " + trials + " times with the hybrid scheme took " + (end - begin) + " milliseconds");

	}
}
