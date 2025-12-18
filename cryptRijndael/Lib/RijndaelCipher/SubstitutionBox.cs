using System;
using Lib.FieldMath;

namespace Lib.RijndaelCipher
{
    public class SubstitutionBox
    {
        private readonly byte[] _sBox;
        private readonly byte[] _invSBox;
        private readonly GF256Service _fieldService;
        private readonly byte _modulus;

        public SubstitutionBox(GF256Service fieldService, byte modulus)
        {
            _fieldService = fieldService;
            _modulus = modulus;
            (_sBox, _invSBox) = GenerateSBoxes();
        }
         
        private (byte[], byte[]) GenerateSBoxes()
        {
            byte[] sBox = new byte[256];
            byte[] invSBox = new byte[256];
            
            for (int i = 0; i < 256; i++)
            {
                byte b = (byte)i;
                
                byte inv;
                try
                {
                    inv = _fieldService.Inverse(b, _modulus);
                }
                catch (ArgumentException)
                {
                    inv = 0; 
                }
                
                sBox[i] = Transform(inv);
                invSBox[sBox[i]] = (byte)i;
            }
            
            return (sBox, invSBox);
        }

        private byte Transform(byte b)
        {
            byte result = 0;
            
            for (int i = 0; i < 8; i++)
            {
                byte bit = (byte)(((b >> i) & 1) ^
                                 ((b >> ((i + 4) % 8)) & 1) ^
                                 ((b >> ((i + 5) % 8)) & 1) ^
                                 ((b >> ((i + 6) % 8)) & 1) ^
                                 ((b >> ((i + 7) % 8)) & 1) ^
                                 ((0x63 >> i) & 1));
                
                result |= (byte)(bit << i);
            }
            
            return result;
        }

        public byte Apply(byte b) => _sBox[b];
        public byte ApplyInverse(byte b) => _invSBox[b];
        
        public void SubstituteBytes(byte[] state)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = Apply(state[i]);
        }
        
        public void InverseSubstituteBytes(byte[] state)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = ApplyInverse(state[i]);
        }
    }
}