using System;

namespace Lib.Crypto
{
    public class ECBMode : IBlockCipherMode
    {
        private IBlockCipher _cipher = null!; // Добавляем = null!
        
        public void Initialize(IBlockCipher cipher, byte[] iv)
        {
            _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        }
        
        public byte[] Encrypt(byte[] data)
        {
            if (_cipher == null) throw new InvalidOperationException("ECBMode not initialized");
            
            int blockSize = _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            
            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(data, i, block, 0, Math.Min(blockSize, data.Length - i));
                byte[] encrypted = _cipher.Encrypt(block);
                Array.Copy(encrypted, 0, result, i, Math.Min(blockSize, data.Length - i));
            }
            
            return result;
        }
        
        public byte[] Decrypt(byte[] data)
        {
            if (_cipher == null) throw new InvalidOperationException("ECBMode not initialized");
            
            int blockSize = _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            
            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(data, i, block, 0, Math.Min(blockSize, data.Length - i));
                byte[] decrypted = _cipher.Decrypt(block);
                Array.Copy(decrypted, 0, result, i, Math.Min(blockSize, data.Length - i));
            }
            
            return result;
        }
    }
    
    public class CBCMode : IBlockCipherMode
    {
        private IBlockCipher _cipher = null!;
        private byte[] _iv = null!;
        private byte[] _currentIV = null!;
        
        public void Initialize(IBlockCipher cipher, byte[] iv)
        {
            _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
            _iv = iv ?? throw new ArgumentNullException(nameof(iv));
            _currentIV = new byte[iv.Length];
            Array.Copy(iv, _currentIV, iv.Length);
        }
        
        public byte[] Encrypt(byte[] data)
        {
            if (_cipher == null || _iv == null || _currentIV == null)
                throw new InvalidOperationException("CBCMode not initialized");
            
            int blockSize = _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            
            Array.Copy(_iv, _currentIV, _iv.Length);
            
            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(data, i, block, 0, Math.Min(blockSize, data.Length - i));
                
                for (int j = 0; j < blockSize; j++)
                    block[j] ^= _currentIV[j];
                
                byte[] encrypted = _cipher.Encrypt(block);
                Array.Copy(encrypted, 0, result, i, Math.Min(blockSize, data.Length - i));
                Array.Copy(encrypted, _currentIV, Math.Min(blockSize, encrypted.Length));
            }
            
            return result;
        }
        
        public byte[] Decrypt(byte[] data)
        {
            if (_cipher == null || _iv == null || _currentIV == null)
                throw new InvalidOperationException("CBCMode not initialized");
            
            int blockSize = _cipher.BlockSize;
            byte[] result = new byte[data.Length];
            
            Array.Copy(_iv, _currentIV, _iv.Length);
            
            for (int i = 0; i < data.Length; i += blockSize)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(data, i, block, 0, Math.Min(blockSize, data.Length - i));
                
                byte[] decrypted = _cipher.Decrypt(block);
                
                for (int j = 0; j < blockSize; j++)
                    decrypted[j] ^= _currentIV[j];
                
                Array.Copy(decrypted, 0, result, i, Math.Min(blockSize, data.Length - i));
                Array.Copy(block, _currentIV, Math.Min(blockSize, block.Length));
            }
            
            return result;
        }
    }
}