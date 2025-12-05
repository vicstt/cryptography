using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using cryptDES.Lib.Interfaces;

namespace cryptDES.Lib.Modes
{
    /// <summary>
    /// Класс, репрезентирующий контекст выполнения симметричного криптографического
    /// алгоритма, предоставляющий объектный функционал по выполнению операций
    /// шифрования и дешифрования заданным ключом симметричного алгоритма с поддержкой
    /// различных режимов шифрования и набивки.
    /// </summary>
    public class CryptoContext
    {
        private readonly ISymmetricCipher _cipher;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;
        private readonly byte[]? _iv;
        private readonly object[]? _additionalModeArgs;
        private readonly object _lock = new object();
        private readonly int _blockSize;

        private byte[] _feedbackRegister = default!;
        private (byte[] Plaintext, byte[] Ciphertext) _pcbcFeedbackRegisters;
        private byte[] _ofbRegister = default!;
        private byte[] _cfbRegister = default!;

        /// <summary>
        /// Конструктор контекста шифрования
        /// </summary>
        /// <param name="cipher">Реализация симметричного алгоритма</param>
        /// <param name="mode">Режим шифрования</param>
        /// <param name="padding">Режим набивки</param>
        /// <param name="iv">Вектор инициализации (опционально)</param>
        /// <param name="additionalModeArgs">Дополнительные параметры для указанного режима</param>
        public CryptoContext(
            ISymmetricCipher cipher,
            CipherMode mode,
            PaddingMode padding,
            byte[]? iv = null,
            params object[] additionalModeArgs)
        {
            _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
            _mode = mode;
            _padding = padding;
            _iv = iv;
            _additionalModeArgs = additionalModeArgs;
            _blockSize = _cipher.BlockSizeInBytes;

            ValidateParameters();
        }

        private void ValidateParameters()
        {
            if (_mode != CipherMode.ECB && _iv == null)
            {
                throw new ArgumentException($"Режим {_mode} требует вектор инициализации");
            }

            if (_iv != null && _iv.Length != _blockSize)
            {
                throw new ArgumentException(
                    $"Размер вектора инициализации ({_iv.Length}) " +
                    $"должен совпадать с размером блока ({_blockSize})");
            }
        }

        #region Основные методы шифрования/дешифрования

        /// <summary>
        /// Инициализирует алгоритм с заданным ключом
        /// </summary>
        /// <param name="key">Ключ шифрования</param>
        public void Initialize(byte[] key)
        {
            _cipher.Initialize(key);
            InitializeState();
        }

        /// <summary>
        /// Шифрует данные
        /// </summary>
        /// <param name="data">Данные для шифрования</param>
        /// <returns>Зашифрованные данные</returns>
        public byte[] Encrypt(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            lock (_lock)
            {
                InitializeState();
                byte[] paddedData = ApplyPadding(data);
                return PerformEncryption(paddedData);
            }
        }

        /// <summary>
        /// Дешифрует данные
        /// </summary>
        /// <param name="data">Данные для дешифрования</param>
        /// <returns>Расшифрованные данные</returns>
        public byte[] Decrypt(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            lock (_lock)
            {
                InitializeState();
                byte[] decryptedData = PerformDecryption(data);
                return RemovePadding(decryptedData);
            }
        }

        /// <summary>
        /// Шифрует данные с возвратом результата через out параметр
        /// </summary>
        /// <param name="data">Данные для шифрования</param>
        /// <param name="result">Зашифрованные данные</param>
        public void Encrypt(byte[] data, out byte[] result)
        {
            result = Encrypt(data);
        }

        /// <summary>
        /// Дешифрует данные с возвратом результата через out параметр
        /// </summary>
        /// <param name="data">Данные для дешифрования</param>
        /// <param name="result">Расшифрованные данные</param>
        public void Decrypt(byte[] data, out byte[] result)
        {
            result = Decrypt(data);
        }

        #endregion

        #region Асинхронные методы

        /// <summary>
        /// Асинхронно шифрует данные
        /// </summary>
        /// <param name="data">Данные для шифрования</param>
        /// <returns>Задача с зашифрованными данными</returns>
        public async Task<byte[]> EncryptAsync(byte[] data) => await Task.Run(() => Encrypt(data));

        /// <summary>
        /// Асинхронно дешифрует данные
        /// </summary>
        /// <param name="data">Данные для дешифрования</param>
        /// <returns>Задача с расшифрованными данными</returns>
        public async Task<byte[]> DecryptAsync(byte[] data) => await Task.Run(() => Decrypt(data));

        #endregion

        #region Работа с файлами

        /// <summary>
        /// Шифрует файл
        /// </summary>
        /// <param name="inputFile">Входной файл</param>
        /// <param name="outputFile">Выходной файл</param>
        public void EncryptFile(string inputFile, string outputFile)
        {
            if (inputFile == null) throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null) throw new ArgumentNullException(nameof(outputFile));

            byte[] data = File.ReadAllBytes(inputFile);
            byte[] encryptedData = Encrypt(data);
            File.WriteAllBytes(outputFile, encryptedData);
        }

        /// <summary>
        /// Дешифрует файл
        /// </summary>
        /// <param name="inputFile">Входной файл</param>
        /// <param name="outputFile">Выходной файл</param>
        public void DecryptFile(string inputFile, string outputFile)
        {
            if (inputFile == null) throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null) throw new ArgumentNullException(nameof(outputFile));

            byte[] data = File.ReadAllBytes(inputFile);
            byte[] decryptedData = Decrypt(data);
            File.WriteAllBytes(outputFile, decryptedData);
        }

        /// <summary>
        /// Асинхронно шифрует файл
        /// </summary>
        /// <param name="inputFile">Входной файл</param>
        /// <param name="outputFile">Выходной файл</param>
        /// <returns>Задача</returns>
        public async Task EncryptFileAsync(string inputFile, string outputFile)
        {
            await Task.Run(() => EncryptFile(inputFile, outputFile));
        }

        /// <summary>
        /// Асинхронно дешифрует файл
        /// </summary>
        /// <param name="inputFile">Входной файл</param>
        /// <param name="outputFile">Выходной файл</param>
        /// <returns>Задача</returns>
        public async Task DecryptFileAsync(string inputFile, string outputFile)
        {
            await Task.Run(() => DecryptFile(inputFile, outputFile));
        }

        #endregion

        #region Работа с потоками

        /// <summary>
        /// Асинхронно шифрует поток данных
        /// </summary>
        /// <param name="inputStream">Входной поток</param>
        /// <param name="outputStream">Выходной поток</param>
        /// <returns>Задача</returns>
        public async Task EncryptAsync(Stream inputStream, Stream outputStream)
        {
            InitializeState();

            // Для надежности читаем весь поток в память
            using var ms = new MemoryStream();
            await inputStream.CopyToAsync(ms);
            byte[] data = ms.ToArray();

            byte[] encryptedData = Encrypt(data);
            await outputStream.WriteAsync(encryptedData, 0, encryptedData.Length);
        }

        /// <summary>
        /// Асинхронно дешифрует поток данных
        /// </summary>
        /// <param name="inputStream">Входной поток</param>
        /// <param name="outputStream">Выходной поток</param>
        /// <returns>Задача</returns>
        public async Task DecryptAsync(Stream inputStream, Stream outputStream)
        {
            InitializeState();

            // Для надежности читаем весь поток в память
            using var ms = new MemoryStream();
            await inputStream.CopyToAsync(ms);
            byte[] data = ms.ToArray();

            byte[] decryptedData = Decrypt(data);
            await outputStream.WriteAsync(decryptedData, 0, decryptedData.Length);
        }

        #endregion

        #region Приватные методы реализации

        private void InitializeState()
        {
            if (_mode != CipherMode.ECB && _iv != null)
            {
                _feedbackRegister = (byte[])_iv.Clone();
                _pcbcFeedbackRegisters = ((byte[])_iv.Clone(), (byte[])_iv.Clone());
                _ofbRegister = (byte[])_iv.Clone();
                _cfbRegister = (byte[])_iv.Clone();
            }
        }

        private byte[] ApplyPadding(byte[] data)
        {
            if (_mode == CipherMode.CTR || _mode == CipherMode.OFB || _mode == CipherMode.CFB)
            {
                return data;
            }

            int blockSize = _blockSize;
            int dataLength = data.Length;
            int paddingLength = blockSize - (dataLength % blockSize);

            if (paddingLength == blockSize && _padding != PaddingMode.PKCS7)
            {
                paddingLength = 0;
            }

            if (paddingLength == 0)
            {
                return (byte[])data.Clone();
            }

            byte[] paddedData = new byte[dataLength + paddingLength];
            Array.Copy(data, 0, paddedData, 0, dataLength);

            switch (_padding)
            {
                case PaddingMode.Zeros:
                    for (int i = dataLength; i < paddedData.Length; i++)
                    {
                        paddedData[i] = 0x00;
                    }
                    break;

                case PaddingMode.ANSI_X923:
                    for (int i = dataLength; i < paddedData.Length - 1; i++)
                    {
                        paddedData[i] = 0x00;
                    }
                    paddedData[paddedData.Length - 1] = (byte)paddingLength;
                    break;

                case PaddingMode.PKCS7:
                    for (int i = dataLength; i < paddedData.Length; i++)
                    {
                        paddedData[i] = (byte)paddingLength;
                    }
                    break;

                case PaddingMode.ISO_10126:
                    var random = new Random();
                    for (int i = dataLength; i < paddedData.Length - 1; i++)
                    {
                        paddedData[i] = (byte)random.Next(0, 256);
                    }
                    paddedData[paddedData.Length - 1] = (byte)paddingLength;
                    break;

                default:
                    throw new NotImplementedException($"Режим набивки {_padding} не реализован");
            }

            return paddedData;
        }

        private byte[] RemovePadding(byte[] data)
        {
            if (_mode == CipherMode.CTR || _mode == CipherMode.OFB || _mode == CipherMode.CFB)
            {
                return data;
            }

            if (data.Length == 0)
            {
                return data;
            }

            switch (_padding)
            {
                case PaddingMode.Zeros:
                    int lastNonZero = Array.FindLastIndex(data, b => b != 0);
                    if (lastNonZero == -1) return Array.Empty<byte>();
                    byte[] resultZeros = new byte[lastNonZero + 1];
                    Array.Copy(data, 0, resultZeros, 0, lastNonZero + 1);
                    return resultZeros;

                case PaddingMode.ANSI_X923:
                    ValidateAndRemoveAnsiX923Padding(data);
                    return RemoveLastBytes(data, data[data.Length - 1]);

                case PaddingMode.PKCS7:
                    ValidateAndRemovePkcs7Padding(data);
                    return RemoveLastBytes(data, data[data.Length - 1]);

                case PaddingMode.ISO_10126:
                    ValidateAndRemoveIso10126Padding(data);
                    return RemoveLastBytes(data, data[data.Length - 1]);

                default:
                    throw new NotImplementedException($"Режим набивки {_padding} не реализован");
            }
        }

        private void ValidateAndRemoveAnsiX923Padding(byte[] data)
        {
            int paddingLength = data[data.Length - 1];
            if (paddingLength <= 0 || paddingLength > data.Length || paddingLength > _blockSize)
            {
                throw new InvalidOperationException("Некорректная длина паддинга ANSI X.923");
            }

            for (int i = data.Length - paddingLength; i < data.Length - 1; i++)
            {
                if (data[i] != 0)
                {
                    throw new InvalidOperationException("Некорректный паддинг ANSI X.923");
                }
            }
        }

        private void ValidateAndRemovePkcs7Padding(byte[] data)
        {
            int paddingLength = data[data.Length - 1];
            if (paddingLength <= 0 || paddingLength > data.Length || paddingLength > _blockSize)
            {
                throw new InvalidOperationException("Некорректная длина паддинга PKCS7");
            }

            for (int i = data.Length - paddingLength; i < data.Length; i++)
            {
                if (data[i] != paddingLength)
                {
                    throw new InvalidOperationException("Некорректный паддинг PKCS7");
                }
            }
        }

        private void ValidateAndRemoveIso10126Padding(byte[] data)
        {
            int paddingLength = data[data.Length - 1];
            if (paddingLength <= 0 || paddingLength > data.Length || paddingLength > _blockSize)
            {
                throw new InvalidOperationException("Некорректная длина паддинга ISO 10126");
            }
        }

        private byte[] RemoveLastBytes(byte[] data, int count)
        {
            if (count <= 0 || count > data.Length) return data;
            byte[] result = new byte[data.Length - count];
            Array.Copy(data, 0, result, 0, result.Length);
            return result;
        }

        private byte[] PerformEncryption(byte[] data)
        {
            if (data.Length % _blockSize != 0)
            {
                throw new InvalidOperationException("Длина данных должна быть кратна размеру блока после набивки");
            }

            byte[] result = new byte[data.Length];

            switch (_mode)
            {
                case CipherMode.ECB:
                    EncryptECB(data, result);
                    break;
                case CipherMode.CBC:
                    EncryptCBC(data, result);
                    break;
                case CipherMode.PCBC:
                    EncryptPCBC(data, result);
                    break;
                case CipherMode.CFB:
                    EncryptCFB(data, result);
                    break;
                case CipherMode.OFB:
                    EncryptOFB(data, result);
                    break;
                case CipherMode.CTR:
                    EncryptCTR(data, result);
                    break;
                case CipherMode.RandomDelta:
                    EncryptRandomDelta(data, result);
                    break;
                default:
                    throw new NotImplementedException($"Режим шифрования {_mode} не реализован");
            }

            return result;
        }

        private byte[] PerformDecryption(byte[] data)
        {
            if (data.Length % _blockSize != 0)
            {
                throw new InvalidOperationException("Длина данных должна быть кратна размеру блока");
            }

            byte[] result = new byte[data.Length];

            switch (_mode)
            {
                case CipherMode.ECB:
                    DecryptECB(data, result);
                    break;
                case CipherMode.CBC:
                    DecryptCBC(data, result);
                    break;
                case CipherMode.PCBC:
                    DecryptPCBC(data, result);
                    break;
                case CipherMode.CFB:
                    DecryptCFB(data, result);
                    break;
                case CipherMode.OFB:
                    DecryptOFB(data, result);
                    break;
                case CipherMode.CTR:
                    DecryptCTR(data, result);
                    break;
                case CipherMode.RandomDelta:
                    DecryptRandomDelta(data, result);
                    break;
                default:
                    throw new NotImplementedException($"Режим дешифрования {_mode} не реализован");
            }

            return result;
        }

        #endregion

        #region Реализации режимов шифрования

        private void EncryptECB(byte[] data, byte[] result)
        {
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);
                
                byte[] outputBlock = _cipher.EncryptBlock(inputBlock);
                Array.Copy(outputBlock, 0, result, offset, _blockSize);
            }
        }

        private void EncryptCBC(byte[] data, byte[] result)
        {
            byte[] previousBlock = (byte[])_feedbackRegister.Clone();
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                XorByteArrays(inputBlock, previousBlock);
                
                byte[] outputBlock = _cipher.EncryptBlock(inputBlock);
                Array.Copy(outputBlock, 0, result, offset, _blockSize);
                
                Array.Copy(outputBlock, previousBlock, _blockSize);
            }
        }

        private void EncryptPCBC(byte[] data, byte[] result)
        {
            byte[] previousPlain = _pcbcFeedbackRegisters.Plaintext;
            byte[] previousCipher = _pcbcFeedbackRegisters.Ciphertext;
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                byte[] temp = new byte[_blockSize];
                XorByteArrays(previousPlain, previousCipher, temp);
                XorByteArrays(inputBlock, temp);
                
                byte[] outputBlock = _cipher.EncryptBlock(inputBlock);
                Array.Copy(outputBlock, 0, result, offset, _blockSize);
                
                Array.Copy(inputBlock, previousPlain, _blockSize);
                Array.Copy(outputBlock, previousCipher, _blockSize);
            }
        }

        private void EncryptCFB(byte[] data, byte[] result)
        {
            byte[] register = (byte[])_cfbRegister.Clone();
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                byte[] keystream = _cipher.EncryptBlock(register);
                
                XorByteArrays(inputBlock, keystream);
                Array.Copy(inputBlock, 0, result, offset, _blockSize);
                
                Array.Copy(inputBlock, register, _blockSize);
            }
        }

        private void EncryptOFB(byte[] data, byte[] result)
        {
            byte[] register = (byte[])_ofbRegister.Clone();
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                byte[] keystream = _cipher.EncryptBlock(register);
                
                XorByteArrays(inputBlock, keystream);
                Array.Copy(inputBlock, 0, result, offset, _blockSize);
                
                Array.Copy(keystream, register, _blockSize);
            }
        }

        private void EncryptCTR(byte[] data, byte[] result)
        {
            byte[] counter = (byte[])_feedbackRegister.Clone();
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                byte[] keystream = _cipher.EncryptBlock(counter);
                
                XorByteArrays(inputBlock, keystream);
                Array.Copy(inputBlock, 0, result, offset, _blockSize);
                
                IncrementCounter(counter);
            }
        }

        private void EncryptRandomDelta(byte[] data, byte[] result)
        {
            byte[] previousBlock = (byte[])_feedbackRegister.Clone();
            int seed = _iv != null ? BitConverter.ToInt32(_iv, 0) : 0;
            var random = new Random(seed);
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                byte[] delta = new byte[_blockSize];
                random.NextBytes(delta);
                
                XorByteArrays(inputBlock, previousBlock);
                XorByteArrays(inputBlock, delta);
                
                byte[] outputBlock = _cipher.EncryptBlock(inputBlock);
                Array.Copy(outputBlock, 0, result, offset, _blockSize);
                
                Array.Copy(outputBlock, previousBlock, _blockSize);
            }
        }

        #endregion

        #region Реализации режимов дешифрования

        private void DecryptECB(byte[] data, byte[] result)
        {
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);
                
                byte[] outputBlock = _cipher.DecryptBlock(inputBlock);
                Array.Copy(outputBlock, 0, result, offset, _blockSize);
            }
        }

        private void DecryptCBC(byte[] data, byte[] result)
        {
            byte[] previousBlock = (byte[])_feedbackRegister.Clone();
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                byte[] decryptedBlock = _cipher.DecryptBlock(inputBlock);
                
                XorByteArrays(decryptedBlock, previousBlock);
                Array.Copy(decryptedBlock, 0, result, offset, _blockSize);
                
                Array.Copy(inputBlock, previousBlock, _blockSize);
            }
        }

        private void DecryptPCBC(byte[] data, byte[] result)
        {
            byte[] previousPlain = _pcbcFeedbackRegisters.Plaintext;
            byte[] previousCipher = _pcbcFeedbackRegisters.Ciphertext;
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                byte[] decryptedBlock = _cipher.DecryptBlock(inputBlock);
                
                byte[] temp = new byte[_blockSize];
                XorByteArrays(previousPlain, previousCipher, temp);
                XorByteArrays(decryptedBlock, temp);
                
                Array.Copy(decryptedBlock, 0, result, offset, _blockSize);
                
                Array.Copy(decryptedBlock, previousPlain, _blockSize);
                Array.Copy(inputBlock, previousCipher, _blockSize);
            }
        }

        private void DecryptCFB(byte[] data, byte[] result)
        {
            byte[] register = (byte[])_cfbRegister.Clone();
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                byte[] keystream = _cipher.EncryptBlock(register);
                
                byte[] outputBlock = new byte[_blockSize];
                Array.Copy(inputBlock, outputBlock, _blockSize);
                XorByteArrays(outputBlock, keystream);
                
                Array.Copy(outputBlock, 0, result, offset, _blockSize);
                
                Array.Copy(inputBlock, register, _blockSize);
            }
        }

        private void DecryptOFB(byte[] data, byte[] result)
        {
            EncryptOFB(data, result);
        }

        private void DecryptCTR(byte[] data, byte[] result)
        {
            EncryptCTR(data, result);
        }

        private void DecryptRandomDelta(byte[] data, byte[] result)
        {
            byte[] previousBlock = (byte[])_feedbackRegister.Clone();
            int seed = _iv != null ? BitConverter.ToInt32(_iv, 0) : 0;
            var random = new Random(seed);
            
            for (int i = 0; i < data.Length / _blockSize; i++)
            {
                int offset = i * _blockSize;
                byte[] inputBlock = new byte[_blockSize];
                Array.Copy(data, offset, inputBlock, 0, _blockSize);

                byte[] decryptedBlock = _cipher.DecryptBlock(inputBlock);
                
                byte[] delta = new byte[_blockSize];
                random.NextBytes(delta);
                
                XorByteArrays(decryptedBlock, previousBlock);
                XorByteArrays(decryptedBlock, delta);
                
                Array.Copy(decryptedBlock, 0, result, offset, _blockSize);
                
                Array.Copy(inputBlock, previousBlock, _blockSize);
            }
        }

        #endregion

        #region Вспомогательные методы

        private static void XorByteArrays(byte[] a, byte[] b, byte[]? result = null)
        {
            result ??= a;
            
            int minLength = Math.Min(a.Length, Math.Min(b.Length, result.Length));
            for (int i = 0; i < minLength; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
        }

        private static void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0) break;
            }
        }

        #endregion
    }
}