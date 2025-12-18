using System;
using Lib.FieldMath;
using Lib.RijndaelCipher.Constants;

namespace Lib.RijndaelCipher
{
    public class MixColumns
    {
        private readonly GF256Service _fieldService;
        private readonly byte _modulus;
        
        public MixColumns(GF256Service fieldService, byte modulus)
        {
            _fieldService = fieldService;
            _modulus = modulus;
        }

        public void Mix(byte[] state)
        {
            int Nb = state.Length / 4;
            
            for (int col = 0; col < Nb; col++)
            {
                int offset = col * 4;
                byte s0 = state[offset];
                byte s1 = state[offset + 1];
                byte s2 = state[offset + 2];
                byte s3 = state[offset + 3];
                
                state[offset] = (byte)(_fieldService.Multiply(0x02, s0, _modulus) ^ 
                                        _fieldService.Multiply(0x03, s1, _modulus) ^ 
                                        s2 ^ s3);
                                        
                state[offset + 1] = (byte)(s0 ^ 
                                          _fieldService.Multiply(0x02, s1, _modulus) ^ 
                                          _fieldService.Multiply(0x03, s2, _modulus) ^ 
                                          s3);
                                          
                state[offset + 2] = (byte)(s0 ^ s1 ^ 
                                          _fieldService.Multiply(0x02, s2, _modulus) ^ 
                                          _fieldService.Multiply(0x03, s3, _modulus));
                                          
                state[offset + 3] = (byte)(_fieldService.Multiply(0x03, s0, _modulus) ^ 
                                          s1 ^ s2 ^ 
                                          _fieldService.Multiply(0x02, s3, _modulus));
            }
        }
        
        public void InverseMix(byte[] state)
        {
            int Nb = state.Length / 4;
            
            for (int col = 0; col < Nb; col++)
            {
                int offset = col * 4;
                byte s0 = state[offset];
                byte s1 = state[offset + 1];
                byte s2 = state[offset + 2];
                byte s3 = state[offset + 3];
                
                state[offset] = (byte)(_fieldService.Multiply(0x0E, s0, _modulus) ^ 
                                        _fieldService.Multiply(0x0B, s1, _modulus) ^ 
                                        _fieldService.Multiply(0x0D, s2, _modulus) ^ 
                                        _fieldService.Multiply(0x09, s3, _modulus));
                                        
                state[offset + 1] = (byte)(_fieldService.Multiply(0x09, s0, _modulus) ^ 
                                          _fieldService.Multiply(0x0E, s1, _modulus) ^ 
                                          _fieldService.Multiply(0x0B, s2, _modulus) ^ 
                                          _fieldService.Multiply(0x0D, s3, _modulus));
                                          
                state[offset + 2] = (byte)(_fieldService.Multiply(0x0D, s0, _modulus) ^ 
                                          _fieldService.Multiply(0x09, s1, _modulus) ^ 
                                          _fieldService.Multiply(0x0E, s2, _modulus) ^ 
                                          _fieldService.Multiply(0x0B, s3, _modulus));
                                          
                state[offset + 3] = (byte)(_fieldService.Multiply(0x0B, s0, _modulus) ^ 
                                          _fieldService.Multiply(0x0D, s1, _modulus) ^ 
                                          _fieldService.Multiply(0x09, s2, _modulus) ^ 
                                          _fieldService.Multiply(0x0E, s3, _modulus));
            }
        }
    }
}