using System;
using cryptDES.Lib.BitUtils;
using cryptDES.Lib.DES;
using cryptDES.Lib.Interfaces;

namespace cryptDES.Lib.DES
{
    public class DESKeyScheduler : IKeyScheduler
    {
        public byte[][] GenerateRoundKeys(byte[] key)
        {
            if (key?.Length != 8) throw new ArgumentException("DES key must be 8 bytes long.", nameof(key));

            byte[] pc1Result = BitPermutation.PermutationBytes(key, DESTables.PC1, false, false); 

            byte[] c = new byte[4]; 
            byte[] d = new byte[4]; 

            ExtractBits(pc1Result, 0, 28, c, 0);
            ExtractBits(pc1Result, 28, 28, d, 0);

            c[3] &= 0x0F;
            d[3] &= 0x0F;

            byte[][] roundKeys = new byte[16][];

            for (int round = 0; round < 16; round++)
            {
                int shift = DESTables.Shifts[round];
                RotateLeft28(c, shift);
                RotateLeft28(d, shift);

                byte[] cd = new byte[7];
                InsertBits(c, 0, 28, cd, 0);
                InsertBits(d, 0, 28, cd, 28);

                byte[] roundKey = BitPermutation.PermutationBytes(cd, DESTables.PC2, false, false); 

                roundKeys[round] = roundKey;
            }

            return roundKeys;
        }

        private static void ExtractBits(byte[] source, int startBitIndexSource, int count, byte[] destination, int startBitIndexDest)
        {
            for (int i = 0; i < count; i++)
            {
                int sourceBitIndex = startBitIndexSource + i;
                int sourceByteIndex = sourceBitIndex / 8;
                int sourceBitInByteIndex = sourceBitIndex % 8;
                bool bitValue = (source[sourceByteIndex] & (1 << sourceBitInByteIndex)) != 0;

                int destBitIndex = startBitIndexDest + i;
                int destByteIndex = destBitIndex / 8;
                int destBitInByteIndex = destBitIndex % 8;
                if (bitValue)
                {
                    destination[destByteIndex] |= (byte)(1 << destBitInByteIndex);
                }
            }
        }

        private static void InsertBits(byte[] source, int startBitIndexSource, int count, byte[] destination, int startBitIndexDest)
        {
            for (int i = 0; i < count; i++)
            {
                int sourceBitIndex = startBitIndexSource + i;
                int sourceByteIndex = sourceBitIndex / 8;
                int sourceBitInByteIndex = sourceBitIndex % 8;
                bool bitValue = (source[sourceByteIndex] & (1 << sourceBitInByteIndex)) != 0;

                int destBitIndex = startBitIndexDest + i;
                int destByteIndex = destBitIndex / 8;
                int destBitInByteIndex = destBitIndex % 8;
                if (bitValue)
                {
                    destination[destByteIndex] |= (byte)(1 << destBitInByteIndex);
                }
                else
                {
                    destination[destByteIndex] &= (byte)~(1 << destBitInByteIndex);
                }
            }
        }

        private static void RotateLeft28(byte[] data, int bits)
        {
            if (bits == 0) return;
            bits = bits % 28;

            byte[] temp = new byte[4];
            ExtractBits(data, 0, 28, temp, 0);

            for (int i = 0; i < 28; i++)
            {
                int fromBitIndex = (i + bits) % 28;
                int toBitIndex = i;

                int fromByteIndex = fromBitIndex / 8;
                int fromBitInByteIndex = fromBitIndex % 8;
                bool bitValue = (temp[fromByteIndex] & (1 << fromBitInByteIndex)) != 0;

                int toByteIndex = toBitIndex / 8;
                int toBitInByteIndex = toBitIndex % 8;
                if (bitValue)
                {
                    data[toByteIndex] |= (byte)(1 << toBitInByteIndex);
                }
                else
                {
                    data[toByteIndex] &= (byte)~(1 << toBitInByteIndex);
                }
            }
        }
    }
}