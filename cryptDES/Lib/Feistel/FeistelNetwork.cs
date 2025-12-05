using System;
using cryptDES.Lib.Interfaces;

namespace cryptDES.Lib.Feistel
{
    public class FeistelNetwork : ISymmetricCipher
    {
        private readonly IKeyScheduler _keyScheduler;
        private readonly IRoundFunction _roundFunction;
        private readonly int _numRounds;
        private readonly int _blockSizeInBytes;
        protected byte[][] _roundKeys = Array.Empty<byte[]>();
        protected readonly object _lock = new object(); 

        public virtual int BlockSizeInBytes => _blockSizeInBytes;

        public FeistelNetwork(IKeyScheduler keyScheduler, IRoundFunction roundFunction, int numRounds, int blockSizeInBytes)
        {
            _keyScheduler = keyScheduler ?? throw new ArgumentNullException(nameof(keyScheduler));
            _roundFunction = roundFunction ?? throw new ArgumentNullException(nameof(roundFunction));
            _numRounds = numRounds;
            _blockSizeInBytes = blockSizeInBytes;
            if (_blockSizeInBytes % 2 != 0) throw new ArgumentException("Block size must be even for Feistel network.");
        }

        /// <summary>
        /// Инициализирует алгоритм с заданным ключом, генерируя раундовые ключи.
        /// </summary>
        /// <param name="key">Ключ шифрования.</param>
        public virtual void Initialize(byte[] key)
        {
            lock (_lock)
            {
                if (key == null) throw new ArgumentNullException(nameof(key));

                _roundKeys = _keyScheduler.GenerateRoundKeys(key);
                if (_roundKeys.Length != _numRounds)
                {
                    throw new InvalidOperationException($"Key scheduler generated {_roundKeys.Length} keys, but {_numRounds} are required.");
                }
            }
        }

        /// <summary>
        /// Шифрует один блок данных.
        /// </summary>
        /// <param name="inputBlock">Входной блок данных.</param>
        /// <returns>Зашифрованный блок данных.</returns>
        public virtual byte[] EncryptBlock(byte[] inputBlock)
        {
            if (inputBlock == null || inputBlock.Length != _blockSizeInBytes) throw new ArgumentException($"Input block size must be {_blockSizeInBytes} bytes.");
            if (_roundKeys.Length == 0) throw new InvalidOperationException("Algorithm must be initialized before use.");

            int halfBlockSize = _blockSizeInBytes / 2;
            byte[] left = new byte[halfBlockSize];
            byte[] right = new byte[halfBlockSize];
            Array.Copy(inputBlock, 0, left, 0, halfBlockSize);
            Array.Copy(inputBlock, halfBlockSize, right, 0, halfBlockSize);

            for (int i = 0; i < _numRounds; i++)
            {
                byte[] fOutput = _roundFunction.ProcessRound(right, _roundKeys[i]);
                XorByteArrays(left, fOutput);
                (left, right) = (right, left);
            }

            byte[] output = new byte[_blockSizeInBytes];
            Array.Copy(left, 0, output, 0, halfBlockSize);
            Array.Copy(right, 0, output, halfBlockSize, halfBlockSize); 
            return output;
        }

        /// <summary>
        /// Расшифровывает один блок данных.
        /// </summary>
        /// <param name="inputBlock">Входной блок данных.</param>
        /// <returns>Расшифрованный блок данных.</returns>
        public virtual byte[] DecryptBlock(byte[] inputBlock)
        {
            if (inputBlock == null || inputBlock.Length != _blockSizeInBytes) throw new ArgumentException($"Input block size must be {_blockSizeInBytes} bytes.");
            if (_roundKeys.Length == 0) throw new InvalidOperationException("Algorithm must be initialized before use.");

            int halfBlockSize = _blockSizeInBytes / 2;
            byte[] left = new byte[halfBlockSize];
            byte[] right = new byte[halfBlockSize];
            Array.Copy(inputBlock, 0, left, 0, halfBlockSize);
            Array.Copy(inputBlock, halfBlockSize, right, 0, halfBlockSize);

            for (int i = _numRounds - 1; i >= 0; i--)
            {
                (left, right) = (right, left);
                byte[] fOutput = _roundFunction.ProcessRound((byte[])right.Clone(), _roundKeys[i]);
                XorByteArrays(left, fOutput);
            }

            byte[] output = new byte[_blockSizeInBytes];
            Array.Copy(left, 0, output, 0, halfBlockSize); 
            Array.Copy(right, 0, output, halfBlockSize, halfBlockSize); 
            return output;
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