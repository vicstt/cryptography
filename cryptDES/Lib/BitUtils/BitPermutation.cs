using System;

namespace cryptDES.Lib.BitUtils
{
    public static class BitPermutation
    {
        public static byte[] PermutationBytes(byte[] inputValue, int[] pBlock, bool indexingRule, bool zeroIndex)
        {
            if (inputValue == null || pBlock == null)
            {
                throw new ArgumentException("Input array or P-Block is null in PermutationBytes");
            }

            var outputBitLength = pBlock.Length;
            var outputByteLength = (outputBitLength + 7) / 8;
            var result = new byte[outputByteLength];
            PermutationBytes(inputValue, pBlock, result, indexingRule, zeroIndex);
            return result;
        }

        public static void PermutationBytes(byte[] inputValue, int[] pBlock, byte[] destination, bool indexingRule, bool zeroIndex)
        {
            if (inputValue == null || pBlock == null || destination == null)
            {
                throw new ArgumentException("Input, P-Block, or destination is null in PermutationBytes");
            }

            if (destination.Length * 8 < pBlock.Length)
            {
                throw new ArgumentException("Destination array is too small for the permutation result.");
            }

            var inputBitLength = inputValue.Length * 8;
            var indexOffset = zeroIndex ? 0 : 1;

            var minIndex = int.MaxValue;
            var maxIndex = int.MinValue;
            foreach (var pValue in pBlock)
            {
                if (pValue < minIndex) minIndex = pValue;
                if (pValue > maxIndex) maxIndex = pValue;
            }

            if (minIndex < indexOffset || maxIndex >= inputBitLength + indexOffset)
            {
                throw new ArgumentException("P-Block contains an index out of the valid range.");
            }

            Array.Clear(destination, 0, destination.Length);

            var pBlockLength = pBlock.Length;
            for (var i = 0; i < pBlockLength; i++)
            {
                var sourceBitIndex = pBlock[i] - indexOffset;
                var bitValue = indexingRule ? GetBitLSB(inputValue, sourceBitIndex) : GetBitMSB(inputValue, sourceBitIndex);

                if (indexingRule)
                {
                    SetBitLSB(destination, i, bitValue);
                }
                else
                {
                    SetBitMSB(destination, i, bitValue);
                }
            }
        }

        private static bool GetBitLSB(byte[] data, int bitIndex)
        {
            var byteIndex = bitIndex >> 3;
            var bitInByte = bitIndex & 7;
            return (data[byteIndex] & (1 << bitInByte)) != 0;
        }

        private static bool GetBitMSB(byte[] data, int bitIndex)
        {
            var byteIndex = bitIndex >> 3;
            var bitInByte = 7 - (bitIndex & 7);
            return (data[byteIndex] & (1 << bitInByte)) != 0;
        }

        private static void SetBitLSB(byte[] data, int bitIndex, bool value)
        {
            var byteIdx = bitIndex >> 3;
            var bitInByteIdx = bitIndex & 7;
            data[byteIdx] = (byte)(value ? (data[byteIdx] | (1 << bitInByteIdx)) : (data[byteIdx] & ~(1 << bitInByteIdx)));
        }

        private static void SetBitMSB(byte[] data, int bitIndex, bool value)
        {
            var byteIdx = bitIndex >> 3;
            var bitInByteIdx = 7 - (bitIndex & 7);
            data[byteIdx] = (byte)(value ? (data[byteIdx] | (1 << bitInByteIdx)) : (data[byteIdx] & ~(1 << bitInByteIdx)));
        }
    }
}