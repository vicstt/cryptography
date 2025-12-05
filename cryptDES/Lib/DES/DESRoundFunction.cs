using System;
using cryptDES.Lib.BitUtils;
using cryptDES.Lib.DES;
using cryptDES.Lib.Interfaces;

namespace cryptDES.Lib.DES
{
    public class DESRoundFunction : IRoundFunction
    {
        public byte[] ProcessRound(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock?.Length != 4 || roundKey?.Length != 6)
                throw new ArgumentException("Input block must be 4 bytes and round key must be 6 bytes for DES round function.");

            byte[] expanded = BitPermutation.PermutationBytes(inputBlock, DESTables.E, false, false);

            for (int i = 0; i < 6; i++)
            {
                expanded[i] ^= roundKey[i];
            }

            byte[] sBoxOutput = new byte[4]; 

            for (int i = 0; i < 8; i++)
            {
                int sBoxStartBitIndex = i * 6;

                int sBoxValue = 0;
                for (int j = 0; j < 6; j++)
                {
                    int bitIndex = sBoxStartBitIndex + j;
                    int byteIndex = bitIndex / 8;
                    int bitInByteIndex = bitIndex % 8;
                    bool bitValue = (expanded[byteIndex] & (1 << bitInByteIndex)) != 0;
                    if (bitValue)
                    {
                        sBoxValue |= (1 << (5 - j)); 
                    }
                }

                int row = (((sBoxValue >> 5) & 1) << 1) | ((sBoxValue >> 0) & 1);
                int col = (sBoxValue >> 1) & 0x0F;

                int sBoxResult = DESTables.S[i, row, col]; 

                int outputByteIndex = i / 2; 
                int nibbleInByte = i % 2; 

                if (nibbleInByte == 0) 
                {
                    sBoxOutput[outputByteIndex] = (byte)sBoxResult;
                }
                else 
                {
                    sBoxOutput[outputByteIndex] |= (byte)(sBoxResult << 4);
                }
            }

            byte[] pPermuted = BitPermutation.PermutationBytes(sBoxOutput, DESTables.P, false, false); 

            return pPermuted; 
        }
    }
}