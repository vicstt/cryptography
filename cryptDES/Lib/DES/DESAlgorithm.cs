using System;
using cryptDES.Lib.Feistel;
using cryptDES.Lib.Interfaces;
using cryptDES.Lib.BitUtils;
using cryptDES.Lib.DES;

namespace cryptDES.Lib.DES
{
    public class DESAlgorithm : FeistelNetwork
    {
        public DESAlgorithm() : base(new DESKeyScheduler(), new DESRoundFunction(), 16, 8)
        {
        }

        public override byte[] EncryptBlock(byte[] inputBlock)
        {
            if (inputBlock?.Length != 8) throw new ArgumentException("DES block size must be 8 bytes.");

            byte[] ipResult = BitPermutation.PermutationBytes(inputBlock, DESTables.IP, false, false); 

            byte[] processed = base.EncryptBlock(ipResult);

            byte[] fpResult = BitPermutation.PermutationBytes(processed, DESTables.FP, false, false); 

            return fpResult;
        }

        public override byte[] DecryptBlock(byte[] inputBlock)
        {
            if (inputBlock?.Length != 8) throw new ArgumentException("DES block size must be 8 bytes.");

            byte[] ipResult = BitPermutation.PermutationBytes(inputBlock, DESTables.IP, false, false); 

            byte[] processed = base.DecryptBlock(ipResult);

            byte[] fpResult = BitPermutation.PermutationBytes(processed, DESTables.FP, false, false); 

            return fpResult;
        }
    }
}