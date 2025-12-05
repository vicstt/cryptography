using System;
using cryptDES.Lib.Interfaces;
using cryptDES.Lib.DES;
using cryptDES.Lib.BitUtils;

namespace cryptDES.Lib.DEAL
{
    public class DESAdapter : IRoundFunction
    {
        private readonly DESKeyScheduler _desKeyScheduler;

        public DESAdapter()
        {
            _desKeyScheduler = new DESKeyScheduler();
        }

        public byte[] ProcessRound(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock?.Length != 8 || roundKey?.Length != 8)
                throw new ArgumentException("Input block and round key for DESAdapter must be 8 bytes (64 bits) long.");

            byte[][] desRoundKeys = _desKeyScheduler.GenerateRoundKeys(roundKey);

            var tempDES = new TemporaryDES(desRoundKeys);
            
            return tempDES.EncryptBlock(inputBlock);
        }

        private class TemporaryDES
        {
            private readonly byte[][] _roundKeys;

            public TemporaryDES(byte[][] roundKeys)
            {
                _roundKeys = roundKeys;
            }

            public byte[] EncryptBlock(byte[] inputBlock)
            {
                if (inputBlock.Length != 8) throw new ArgumentException("DES block size must be 8 bytes.");

                byte[] data = BitPermutation.PermutationBytes(inputBlock, DESTables.IP, false, false);

                int halfSize = 4;
                byte[] left = new byte[halfSize];
                byte[] right = new byte[halfSize];
                Array.Copy(data, 0, left, 0, halfSize);
                Array.Copy(data, halfSize, right, 0, halfSize);

                var roundFunction = new DESRoundFunction();

                for (int i = 0; i < 16; i++)
                {
                    byte[] fOutput = roundFunction.ProcessRound((byte[])right.Clone(), _roundKeys[i]);
                    XorByteArrays(left, fOutput);
                    (left, right) = (right, left);
                }

                (left, right) = (right, left);

                byte[] result = new byte[8];
                Array.Copy(left, 0, result, 0, halfSize);
                Array.Copy(right, 0, result, halfSize, halfSize);

                return BitPermutation.PermutationBytes(result, DESTables.FP, false, false);
            }

            private static void XorByteArrays(byte[] a, byte[] b)
            {
                for (int i = 0; i < a.Length && i < b.Length; i++)
                {
                    a[i] ^= b[i];
                }
            }
        }
    }
}