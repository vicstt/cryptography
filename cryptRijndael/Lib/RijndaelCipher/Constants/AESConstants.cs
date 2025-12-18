using System;

namespace Lib.RijndaelCipher.Constants
{
    public static class AESConstants
    {
        public static int GetRounds(KeySize keySize, BlockSize blockSize)
        {
            int Nk = (int)keySize / 4;
            int Nb = (int)blockSize / 4;
            return Math.Max(Nk, Nb) + 6;
        }
        
        public static readonly byte[] Rcon = 
        {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        };
    }
}