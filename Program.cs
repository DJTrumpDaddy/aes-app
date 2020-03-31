/*
 *	The following program contains code from an foreign source.
 *	Code that has been directly copied from the source is meant only to generate the S-Box
 *	and Rcon round-key constants instead of implementing an insecure
 *	lookup table. Other code has been modified for my use and has been explicitly marked as
 *	such with comments. A licence to use this foreign code has been included with
 *	the package and is located within the package's root directory. Caution, although
 *	I hope nobody would be inclined to use an amateur AES implementation in a professional setting, this
 *  code may be considered COPYLEFT and is provided "AS IS".
*/




using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace aes_app
{
    class Program
    {
        static readonly uint Nb = 4, Nk = 4, Nr = 10;
		static uint[] key, w;
    	static void Main(string[] args)
		{
			GenSBox();
			GenKey();
			Console.Write("Key: ");
			foreach(uint k in key)
			{
				Console.Write(k.ToString("x8"));
			}

			KeyExpansion();

			uint[] input = new uint[]{0x00112233,0x44556677,0x8899aabb,0xccddeeff};
			uint[] output = new uint[4];

			Console.Write("\nEncrypt IN: ");
			foreach(uint i in input)
			{
				Console.Write(i.ToString("x8"));
			}

			AESEncrypt crypt = new AESEncrypt(w, Nb, Nr, Nk);
			crypt.Cipher(input, ref output);

			Console.Write("\nEncrypt OUT: ");
			foreach(uint o in output)
			{
				Console.Write(o.ToString("x8"));
			}

			Console.Write("\nDecrypt IN: ");
			foreach(uint o in output)
			{
				Console.Write(o.ToString("x8"));
			}

			AESDecrypt dcrypt = new AESDecrypt(w, Nb, Nr, Nk);
			dcrypt.InvCipher(output, ref output);

			Console.Write("\nDecrypt OUT: ");
			foreach(uint o in output)
			{
				Console.Write(o.ToString("x8"));
			}
			Console.WriteLine();
    	}

		static void GenKey()
		{
			/*key = new uint[] {(0x30 << 24) | (0x31 << 16) | (0x32 << 8) | 0x33,
								(0x34 << 24) | (0x35 << 16) | (0x36 << 8) | 0x37,
								(0x38 << 24) | (0x39 << 16) | (0x3a << 8) | 0x3b,
								(0x3c << 24) | (0x3d << 16) | (0x3e << 8) | 0x3f};
								*/
			key = new uint[] {(0x00 << 24) | (0x01 << 16) | (0x02 << 8) | 0x03,
								(0x04 << 24) | (0x05 << 16) | (0x06 << 8) | 0x07,
								(0x08 << 24) | (0x09 << 16) | (0x0a << 8) | 0x0b,
								(0x0c << 24) | (0x0d << 16) | (0x0e << 8) | 0x0f};
		}

		static void KeyExpansion()
		{
			w = new uint[Nb*(Nr+1)];
			uint temp;
			for(int i = 0; i < Nk; i++)
			{
				w[i] = key[i];
			}

			for(uint i = Nk; i < (Nb*(Nr+1)); i++)
			{
				temp = w[i-1];

				if((i % Nk) == 0)
				{
					temp = SubWord(temp) ^ Rcon[i/Nk - 1];
				}

				w[i] = w[i-Nk] ^ temp;				
			}
		}

		public static uint RotateRight(uint x, int rot)
		{
			return (x >> rot) | x << (0x20 - rot);
		}

		/*
		 * Below is the foreign code as mentioned
		 * in the header. I kept this separate
		 * for simplicity in your auditing whether or
		 * not this is plagiarism.
		*/

		/* mul2(x) is used for Rcon[] generation
		*/
    	public static uint mul2(uint x)
		{
			x <<= 1; // x*A(X)
			return x ^ ((uint)(-(int)(x >> 8)) & 0x11B); // x*A(X) mod P(X)
		}

		// multiply with (x + 1) within GF(2^8)
		public static uint mul3(uint x)
		{
			return x ^ mul2(x);
		}

		//multiply with (x^3 + 1) within GF (2^8)
		public static uint mul9(uint x)
		{
			return x ^ mul2(mul2(mul2(x)));
		}

		//multiply with (x^3 + x + 1) within GF(2^8)
		public static uint mulb(uint x)
		{
			return x ^ mul2(x) ^ mul2(mul2(mul2(x)));
		}

		//multiply with (x^3 + x^2 + 1) within GF(2^8)
		public static uint muld(uint x)
		{
			return x ^ mul2(mul2(x)) ^ mul2(mul2(mul2(x)));
		}

		//multiply with (x^3 + x^2 + x) within GF(2^8)
		public static uint mule(uint x)
		{
			return mul2(x) ^ mul2(mul2(x)) ^ mul2(mul2(mul2(x)));
		}

		/* aff(x) is used for S-Box generation
		*/
		static uint aff(uint x)
		{
			// the following operation allows the
			// LSB and MSB to play together
			// in the operation after

			// visual representation of this function
			// is included with this package under the
			// name Sample_affine.txt

			x |= x << 8; 
			x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7) ^ 0x63;
			return x & 0xFF;
		}

		static uint[] Rcon;
		public static uint[] S {get; set;}
		public static uint[] iS {get; set;}

		/* SubWord() combines the RotWord()
		*  and SubWord() functions
		*  by performing the necessary bitwise
		*  permutations within the S-Box
		*  element references.
		*  Although this method was derived from
		*  Pornin's program, it has been modified
		*  to incorporate the RotWord step
		*/
		static uint SubWord(uint x)
		{
			return S[x >> 24]
				| (S[(x >> 16) & 0xFF] << 24)
				| (S[(x >> 8) & 0xFF] << 16)
				| (S[x & 0xFF] << 8);
		}

		static void GenSBox()
		{
			/*
			* The Rcon[] constants are used in the key schedule.
			*/
			Rcon = new uint[Nr];
			uint x = 1;
			for (int i = 0; i < Rcon.Length; i ++) {
				Rcon[i] = x << 24;
				x = mul2(x);
			}

			/*
			* Generate the map x -> 3^x in GF(2^8). "3" (x + 1) happens to
			* be a generator for GF(2^8)*, so we get all 255 non-zero
			* elements.
			*/
			uint[] pow3 = new uint[255];
			x = 1;
			for (int i = 0; i < 255; i ++) {
				pow3[i] = x;
				x = mul3(x); // [x*A(X) mod P(X)] + A(X)
			}

			/*
			* Compute the log3 map 3^x -> x that maps any non-zero
			* element in GF(2^8) to its logarithm in base 3 (in the
			* 0..254 range).
			*/
			int[] log3 = new int[256];
			for (int i = 0; i < 255; i ++) {
				log3[pow3[i]] = i;
			}

			/*
			* Compute the S-box.
			*/
			S = new uint[256];
			S[0] = aff(0);
			S[1] = aff(1);
			for (uint y = 2; y < 0x100; y ++) {
				S[y] = aff(pow3[255 - log3[y]]);
			}

			/*
			* Compute the inverse S-box (for decryption).
			*/
			iS = new uint[256];
			for (uint y = 0; y < 0x100; y ++) {
				iS[S[y]] = y;
			}
		}
	}
}