using System;

namespace aes_app
{
    public class AESDecrypt
    {
        private uint Nb, Nr, Nk;
        private uint[] w, state;
        public AESDecrypt(uint[] w, uint Nb, uint Nr, uint Nk)
        {
            this.w = w;
            this.Nb = Nb;
            this.Nr = Nr;
            this.Nk = Nk;
        }

        public void InvCipher(uint[] input, ref uint[] output)
		{
			state = input;

			AddRoundKey(Nr);
			for(uint round = Nr-1; round > 0; round--)
			{
                InvShiftRows();
				InvSubBytes();
                AddRoundKey(round);
				InvMixColumns();
				Console.WriteLine();
				foreach(uint s in state)
				{
					Console.Write(Convert.ToString(s, 16));
				}
			}

            InvShiftRows();
			InvSubBytes();
			AddRoundKey(0);

			Console.WriteLine();
			foreach(uint s in state)
			{
				Console.Write(Convert.ToString(s, 16));
			}

			output = state;
		}

		private void AddRoundKey(uint round)
		{
			Console.WriteLine($"\nRound {round}");
			for(int c = 0; c < 4; c++)
			{
				state[c] ^= w[(round * Nb) + c];
				Console.Write(Convert.ToString(w[(round * Nb) + c],16));
			}
		}

		private void InvSubBytes()
		{
			uint[] temp = new uint[state.Length];
			for(int r = 0; r < 4; r++)
			{
				for(int c = 0; c < Nb; c++)
				{
					temp[c] |= Program.iS[(state[c] & (0xff000000 >> 0x08 * r)) >> (0x18 - 0x08*r)] << (0x18 - 0x08*r);
				}
			}

			state = temp;
		}

		private void InvShiftRows()
		{
			uint[] temp = new uint[state.Length];
			for(int c = 0; c < Nb; c++)
			{
				temp[c] |= 	(state[c % 4] & 0xff000000) | 
							(state[(c + 3) % 4] & 0x00ff0000) | 
							(state[(c + 2) % 4] & 0x0000ff00) | 
							(state[(c + 1) % 4] & 0x000000ff);
			}

			state = temp;
		}

		private void InvMixColumns()
		{
			uint[] temp = new uint[state.Length];
			for(int c = 0; c < Nb; c++)
			{
				for(int r = 0; r < 4; r++)
				{
					temp[c] |= 	Program.RotateRight((Program.mule((state[c] & Program.RotateRight(0xff000000, 0x08 * r)) >> (0x18 - 0x08 * r))) ^
											(Program.mulb((state[c] & Program.RotateRight(0x00ff0000, 0x08 * r)) >> (0x10 - 0x08 * ((r + 1)%4 - 1)))) ^
											(Program.muld((state[c] & Program.RotateRight(0x0000ff00, 0x08 * r)) >> (0x08 - 0x08 * ((r + 2)%4 - 2)))) ^
											(Program.mul9((state[c] & Program.RotateRight(0x000000ff, 0x08 * r)) >> (-0x08 * ((r + 3)%4 - 3)))), 0x08 * (r + 1));
				}
			}

			state = temp;
		}
    }
}