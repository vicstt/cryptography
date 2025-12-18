using System;
using Lib.Crypto;
using Lib.FieldMath;
using Lib.RijndaelCipher.Constants;

namespace Lib.RijndaelCipher
{
    public class RijndaelCipher : IBlockCipher
    {
        private readonly GF256Service _fieldService;
        private readonly BlockSize _blockSize;
        private readonly KeySize _keySize;
        private readonly byte _modulus;
        
        private KeySchedule? _keySchedule;
        private SubstitutionBox? _sBox;
        private MixColumns? _mixColumns;
        
        public int BlockSize => (int)_blockSize;
        
        public RijndaelCipher(GF256Service fieldService, 
                            BlockSize blockSize, 
                            KeySize keySize, 
                            byte modulus)
        {
            _fieldService = fieldService;
            _blockSize = blockSize;
            _keySize = keySize;
            _modulus = modulus;
        }
        
        public void Initialize(byte[] key)
        {
            if (key.Length != (int)_keySize)
                throw new ArgumentException($"Неверный размер ключа. Ожидалось {_keySize} байт");
                
            _keySchedule = new KeySchedule(key, _keySize, _blockSize, _fieldService, _modulus);
            _sBox = new SubstitutionBox(_fieldService, _modulus);
            _mixColumns = new MixColumns(_fieldService, _modulus);
        }
          
        public byte[] Encrypt(byte[] block)
        {
            ValidateBlock(block);
            EnsureInitialized();
            
            byte[] state = new byte[block.Length];
            Array.Copy(block, state, block.Length);
            
            AddRoundKey(state, 0);
            
            for (int round = 1; round < _keySchedule!.Rounds; round++)
            {
                _sBox!.SubstituteBytes(state);
                ShiftRows(state);
                _mixColumns!.Mix(state);
                AddRoundKey(state, round);
            }
            
            _sBox!.SubstituteBytes(state);
            ShiftRows(state);
            AddRoundKey(state, _keySchedule.Rounds);
            
            return state;
        }
        
        public byte[] Decrypt(byte[] block)
        {
            ValidateBlock(block);
            EnsureInitialized();
            
            byte[] state = new byte[block.Length];
            Array.Copy(block, state, block.Length);
            
            AddRoundKey(state, _keySchedule!.Rounds);
            InverseShiftRows(state);
            _sBox!.InverseSubstituteBytes(state);
            
            for (int round = _keySchedule.Rounds - 1; round >= 1; round--)
            {
                AddRoundKey(state, round);
                _mixColumns!.InverseMix(state);
                InverseShiftRows(state);
                _sBox!.InverseSubstituteBytes(state);
            }
            
            AddRoundKey(state, 0);
            
            return state;
        }
        
        private void AddRoundKey(byte[] state, int round)
        {
            byte[] roundKey = _keySchedule!.GetRoundKey(round, state.Length);
            
            for (int i = 0; i < state.Length; i++)
                state[i] ^= roundKey[i];
        }
        
        private void ShiftRows(byte[] state)
        {
            int Nb = state.Length / 4; 
            byte[] temp = new byte[Nb];
            
            for (int row = 1; row < 4; row++)
            {
                for (int col = 0; col < Nb; col++)
                    temp[col] = state[row + col * 4];
                    
                for (int col = 0; col < Nb; col++)
                    state[row + col * 4] = temp[(col + row) % Nb];
            }
        }
        
        private void InverseShiftRows(byte[] state)
        {
            int Nb = state.Length / 4;
            byte[] temp = new byte[Nb];
            
            for (int row = 1; row < 4; row++)
            {
                for (int col = 0; col < Nb; col++)
                    temp[col] = state[row + col * 4];
                    
                for (int col = 0; col < Nb; col++)
                    state[row + col * 4] = temp[(col - row + Nb) % Nb];
            }
        }
        
        private void ValidateBlock(byte[] block)
        {
            if (block == null)
                throw new ArgumentNullException(nameof(block));
                
            if (block.Length != (int)_blockSize)
                throw new ArgumentException($"Неверный размер блока. Ожидалось {_blockSize} байт, получено {block.Length} байт");
        }
        
        private void EnsureInitialized()
        {
            if (_keySchedule == null || _sBox == null || _mixColumns == null)
                throw new InvalidOperationException("Шифр не инициализирован. Вызовите Initialize() перед использованием.");
        }
    }
}