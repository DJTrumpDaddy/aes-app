using System;


namespace aes_app
{
    public class AESEncrypt
    {
        private uint Nb, Nr, Nk;
        private uint[] w, state;
        public AESEncrypt(uint[] w, uint Nb, uint Nr, uint Nk)
        {
            this.w = w;
            this.Nb = Nb;
            this.Nr = Nr;
            this.Nk = Nk;
        }
        public void Cipher(uint[] input, ref uint[] output)
		{
			//state is now a reference to input
			//maybe fix later???

			state = input;

			AddRoundKey(0);
			for(uint round = 1; round < Nr; round++)
			{
				SubBytes();
				ShiftRows();
				MixColumns();
				AddRoundKey(round);
			}

			SubBytes();
			ShiftRows();
			AddRoundKey(Nr);

			output = state;
		}

		private void AddRoundKey(uint round)
		{
			for(int c = 0; c < 4; c++)
			{
				state[c] ^= w[(round * Nb) + c];
			}
		}

		private void SubBytes()
		{
			uint[] temp = new uint[state.Length];
			for(int r = 0; r < 4; r++)
			{
				for(int c = 0; c < Nb; c++)
				{
					temp[c] |= Program.S[(state[c] & (0xff000000 >> 0x08 * r)) >> (0x18 - 0x08*r)] << (0x18 - 0x08*r);
				}
			}

			state = temp;
		}

		private void ShiftRows()
		{
			uint[] temp = new uint[state.Length];
			for(int c = 0; c < Nb; c++)
			{
				temp[c] |= 	(state[c % 4] & 0xff000000) | 
							(state[(c + 1) % 4] & 0x00ff0000) | 
							(state[(c + 2) % 4] & 0x0000ff00) | 
							(state[(c + 3) % 4] & 0x000000ff);
			}

			state = temp;
		}

		private void MixColumns()
		{
			uint[] temp = new uint[state.Length];
			for(int c = 0; c < Nb; c++)
			{
				for(int r = 0; r < 4; r++)
				{
					temp[c] |= 	Program.RotateRight((Program.mul2((state[c] & Program.RotateRight(0xff000000, 0x08 * r)) >> (0x18 - 0x08 * r))) ^
											(Program.mul3((state[c] & Program.RotateRight(0x00ff0000, 0x08 * r)) >> (0x10 - 0x08 * ((r + 1)%4 - 1)))) ^
											((state[c] & Program.RotateRight(0x0000ff00, 0x08 * r)) >> (0x08 - 0x08 * ((r + 2)%4 - 2))) ^
											((state[c] & Program.RotateRight(0x000000ff, 0x08 * r)) >> (-0x08 * ((r + 3)%4 - 3))), 0x08 * (r + 1));
				}
			}

			state = temp;
		}
    }
}