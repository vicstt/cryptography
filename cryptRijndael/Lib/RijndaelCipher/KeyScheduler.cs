using System;
using Lib.FieldMath;
using Lib.RijndaelCipher.Constants;

namespace Lib.RijndaelCipher
{
    public class KeySchedule
    {
        private readonly byte[][] _roundKeys;
        private readonly int _rounds;
        
        public int Rounds => _rounds;
        
        public KeySchedule(byte[] key, KeySize keySize, BlockSize blockSize, 
                          GF256Service fieldService, byte modulus)
        {
            int Nk = (int)keySize / 4;
            int Nb = (int)blockSize / 4;
            _rounds = AESConstants.GetRounds(keySize, blockSize);
            
            _roundKeys = ExpandKey(key, Nk, Nb, fieldService, modulus);
        }
        
        private byte[][] ExpandKey(byte[] key, int Nk, int Nb, 
                                  GF256Service fieldService, byte modulus)
        {
            int totalWords = Nb * (_rounds + 1);
            byte[][] W = new byte[totalWords][];
            
            var sBox = new SubstitutionBox(fieldService, modulus);
            
            for (int i = 0; i < Nk; i++)
            {
                W[i] = new byte[4];
                Array.Copy(key, i * 4, W[i], 0, 4);
            }
            
            for (int i = Nk; i < totalWords; i++)
            {
                byte[] temp = new byte[4];
                Array.Copy(W[i - 1], temp, 4);
                
                if (i % Nk == 0)
                {
                    byte tmp = temp[0];
                    temp[0] = temp[1];
                    temp[1] = temp[2];
                    temp[2] = temp[3];
                    temp[3] = tmp;
                    
                    for (int j = 0; j < 4; j++)
                        temp[j] = sBox.Apply(temp[j]);
                    
                    int rconIndex = i / Nk - 1;
                    if (rconIndex < AESConstants.Rcon.Length)
                        temp[0] ^= AESConstants.Rcon[rconIndex];
                }
                else if (Nk > 6 && i % Nk == 4)
                {
                    for (int j = 0; j < 4; j++)
                        temp[j] = sBox.Apply(temp[j]);
                }
                
                W[i] = new byte[4];
                for (int j = 0; j < 4; j++)
                    W[i][j] = (byte)(W[i - Nk][j] ^ temp[j]);
            }
            
            return W;
        }
        
        public byte[] GetRoundKey(int round, int blockBytes)
        {
            byte[] roundKey = new byte[blockBytes];
            
            for (int i = 0; i < blockBytes / 4; i++)
            {
                byte[] word = _roundKeys[round * (blockBytes / 4) + i];
                Array.Copy(word, 0, roundKey, i * 4, 4);
            }
            
            return roundKey;
        }
    }
}