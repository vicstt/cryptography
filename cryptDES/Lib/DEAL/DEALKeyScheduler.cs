using System;
using cryptDES.Lib.Interfaces;
using cryptDES.Lib.DES;

namespace cryptDES.Lib.DEAL
{
    public class DEALKeyScheduler : IKeyScheduler
    {
        public enum KeySize
        {
            SIZE_128 = 16, 
            SIZE_192 = 24,
            SIZE_256 = 32 
        }

        private readonly int _keySizeInBytes;
        private readonly DESKeyScheduler _desKeyScheduler;

        public DEALKeyScheduler(int keySizeInBytes)
        {
            _keySizeInBytes = keySizeInBytes;
            if (_keySizeInBytes != 16 && _keySizeInBytes != 24 && _keySizeInBytes != 32)
                throw new ArgumentException("DEAL key size must be 128, 192, or 256 bits (16, 24, or 32 bytes).");
            
            _desKeyScheduler = new DESKeyScheduler();
        }

        public byte[][] GenerateRoundKeys(byte[] key)
        {
            if (key?.Length != _keySizeInBytes)
                throw new ArgumentException($"Key length must be {_keySizeInBytes} bytes for DEAL key scheduler.");

            byte[][] dealRoundKeys = new byte[16][];

            for (int i = 0; i < 16; i++)
            {
                byte[] ki;
                
                if (_keySizeInBytes == 16) 
                {
                    ki = (i % 2 == 0) ? GetKeySegment(key, 0, 8) : GetKeySegment(key, 8, 8);
                }
                else if (_keySizeInBytes == 24) 
                {
                    int segmentIndex = i % 3;
                    ki = GetKeySegment(key, segmentIndex * 8, 8);
                }
                else 
                {
                    int segmentIndex = i % 4;
                    ki = GetKeySegment(key, segmentIndex * 8, 8);
                }

                dealRoundKeys[i] = ki;
            }

            return dealRoundKeys;
        }

        private byte[] GetKeySegment(byte[] key, int start, int length)
        {
            byte[] segment = new byte[length];
            Array.Copy(key, start, segment, 0, length);
            return segment;
        }
    }
}