using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using Xunit; 
using cryptDES.Lib.DES;
using cryptDES.Lib.DEAL;
using cryptDES.Lib.Modes;
using cryptDES.Lib.Interfaces;
using cryptDES.Lib.BitUtils;

namespace cryptDES.Tests
{
    public class IntegrationTests
    {
        [Fact]
        public async Task Bit_Permutation_Tests_Should_Pass()
        {
            var success = await TestBitPermutationComprehensive();
            Assert.True(success, "Bit Permutation Tests failed.");
        }

        [Fact]
        public async Task DES_Algorithm_Tests_Should_Pass()
        {
            var success = await TestDESComprehensive();
            Assert.True(success, "DES Algorithm Tests failed.");
        }

        [Fact]
        public async Task Cipher_Mode_Tests_Should_Pass()
        {
            var success = await TestAllCipherModes();
            Assert.True(success, "Cipher Mode Tests failed.");
        }

        [Fact]
        public async Task Padding_Mode_Tests_Should_Pass()
        {
            var success = await TestAllPaddingModes();
            Assert.True(success, "Padding Mode Tests failed.");
        }

        [Fact]
        public async Task DEAL_Algorithm_Tests_Should_Pass()
        {
            var success = await TestDEALComprehensive();
            Assert.True(success, "DEAL Algorithm Tests failed.");
        }

        [Fact]
        public async Task Performance_Tests_Should_Pass()
        {
            var success = await TestPerformance();
            Assert.True(success, "Performance Tests failed.");
        }

        [Fact]
        public async Task File_Processing_Tests_Should_Pass()
        {
            var success = await TestFileProcessing();
            Assert.True(success, "File Processing Tests failed.");
        }

        [Fact]
        public async Task Edge_Case_Tests_Should_Pass()
        {
            var success = await TestEdgeCases();
            Assert.True(success, "Edge Case Tests failed.");
        }

        [Fact]
        public async Task Image_Encryption_Tests_Should_Pass()
        {
            var success = await TestImageEncryption();
            Assert.True(success, "Image Encryption Tests failed.");
        }

        static void CheckResult(string testName, byte[] actual, byte[] expected)
        {
            Assert.True(expected.SequenceEqual(actual), 
                $"Test '{testName}' failed. Expected: {BitConverter.ToString(expected)}, Actual: {BitConverter.ToString(actual)}");
        }

        static void CheckResult(string testName, bool condition, string message = "")
        {
            Assert.True(condition, $"Test '{testName}' failed. {message}");
        }

        #region 1. Тесты битовых перестановок
        static async Task<bool> TestBitPermutationComprehensive()
        {
            return await Task.Run(() =>
            {
                Debug.WriteLine("Testing various bit permutation scenarios...");
                bool allTestsPassed = true;

                try
                {
                    // Тест 1: Простая перестановка байтов
                    byte[] input1 = { 0b10101010, 0b01010101 };
                    int[] permutation1 = { 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 };
                    byte[] expected1 = { 0b01010101, 0b10101010 };
                    byte[] result1 = BitPermutation.PermutationBytes(input1, permutation1, true, true);
                    CheckResult("Byte swap LSB 0-based", result1, expected1);

                    // Тест 2: Та же перестановка но с MSB-first, 0-based
                    byte[] expected2_msb = { 0x55, 0xAA };
                    byte[] result1_msb = BitPermutation.PermutationBytes(input1, permutation1, false, true); 
                    CheckResult("Byte swap MSB 0-based", result1_msb, expected2_msb);

                    // Тест 3: 1-based индексирование, swap байтов
                    byte[] input2 = { 0xFF, 0x00 };
                    int[] permutation2 = { 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8 };
                    byte[] expected3 = { 0x00, 0xFF };
                    byte[] result2 = BitPermutation.PermutationBytes(input2, permutation2, true, false);
                    CheckResult("Byte swap LSB 1-based", result2, expected3);
                    Debug.WriteLine($"  1-based indexing test: {(result2.SequenceEqual(expected3) ? "PASS" : "FAIL")}");

                    // Тест 4: Перестановка 8 бит (1 байт), LSB-first, 1-based
                    byte[] input3 = { 0b11110000 };
                    int[] permutation3 = { 5, 6, 7, 8, 1, 2, 3, 4 };
                    byte[] expected4 = { 0x0F };
                    byte[] result3 = BitPermutation.PermutationBytes(input3, permutation3, true, false);
                    CheckResult("8-bit swap halves LSB 1-based", result3, expected4);
                    Debug.WriteLine($"  8-bit permutation test: {(result3.SequenceEqual(expected4) ? "PASS" : "FAIL")}");

                    // Тест 5: Реальные таблицы из DES (IP - 64 бита, MSB-first, 1-based)
                    byte[] input4 = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
                    byte[] result4 = BitPermutation.PermutationBytes(input4, DESTables.IP, false, false);
                    CheckResult("DES IP permutation length check", new byte[] { (byte)result4.Length }, new byte[] { 8 });
                    byte[] fpResult = BitPermutation.PermutationBytes(result4, DESTables.FP, false, false);
                    CheckResult("DES IP permutation", input4, fpResult);
                    Debug.WriteLine($"  DES IP permutation test: {(input4.SequenceEqual(fpResult) ? "PASS" : "FAIL")}");

                    // Тест 6: Проверка ошибок - неверные индексы (должен бросить исключение)
                    try
                    {
                        byte[] input5 = { 0x01 };
                        int[] badPermutation = { 10, 11, 12 };
                        var result5 = BitPermutation.PermutationBytes(input5, badPermutation, true, false);
                        allTestsPassed = false;
                        Debug.WriteLine("  Error handling test: FAIL (should have thrown exception)");
                    }
                    catch (ArgumentException)
                    {
                        Debug.WriteLine("  Error handling test: PASS");
                    }

                    // Тест 7: Проверка разных комбинаций индексирования
                    byte[] input6 = { 0b11001100, 0b00110011 };

                    int[] perm6_lsb0 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
                    byte[] result6_lsb0 = BitPermutation.PermutationBytes(input6, perm6_lsb0, true, true);
                    CheckResult("LSB 0-based identity", result6_lsb0, input6);

                    int[] perm6_msb1 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
                    byte[] result6_msb1 = BitPermutation.PermutationBytes(input6, perm6_msb1, false, false);
                    CheckResult("MSB 1-based identity", result6_msb1, input6);

                    Debug.WriteLine($"Bit permutation tests: {(allTestsPassed ? "PASS" : "FAIL")}");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Bit permutation tests ERROR: {ex.Message}");
                    Debug.WriteLine($"Stack trace: {ex.StackTrace}");
                    allTestsPassed = false;
                }

                return allTestsPassed;
            });
        }
        #endregion

        #region 2. Тесты DES
        static async Task<bool> TestDESComprehensive()
        {
            return await Task.Run(() =>
            {
                Debug.WriteLine("Testing DES algorithm comprehensively...");
                bool allTestsPassed = true;

                byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
                byte[] plaintext = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

                // Тест 1: Базовое шифрование/дешифрование
                var des = new DESAlgorithm();
                des.Initialize(key);

                byte[] ciphertext = des.EncryptBlock(plaintext);
                byte[] decrypted = des.DecryptBlock(ciphertext);

                CheckResult("DES encrypt/decrypt", decrypted, plaintext);

                // Тест 2: Множественные раунды
                for (int i = 0; i < 5; i++)
                {
                    byte[] temp = des.EncryptBlock(plaintext);
                    byte[] tempDec = des.DecryptBlock(temp);
                    CheckResult($"DES round {i}", tempDec, plaintext);
                }

                // Тест 3: Разные ключи
                byte[] key2 = { 0x0E, 0x32, 0x92, 0x32, 0xEA, 0x6D, 0x0D, 0x73 };
                des.Initialize(key2);
                byte[] cipher2 = des.EncryptBlock(plaintext);
                byte[] decrypted2 = des.DecryptBlock(cipher2);
                CheckResult("DES different key", decrypted2, plaintext);

                // Тест 4: Проверка, что разные ключи дают разный результат
                allTestsPassed &= !ciphertext.SequenceEqual(cipher2);

                Debug.WriteLine($"DES comprehensive tests: {(allTestsPassed ? "PASS" : "FAIL")}");
                return allTestsPassed;
            });
        }
        #endregion

        #region 3. Тесты всех режимов шифрования
        static async Task<bool> TestAllCipherModes()
        {
            return await Task.Run(() =>
            {
                Debug.WriteLine("Testing all cipher modes with various scenarios...");
                bool allTestsPassed = true;

                byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
                byte[] iv = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

                byte[][] testData = {
                    new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
                    new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
                    new byte[64]
                };
                new Random(42).NextBytes(testData[2]);

                var modes = new[] { CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR };

                foreach (var mode in modes)
                {
                    Debug.WriteLine($"  Testing mode: {mode}");

                    try
                    {
                        bool modePassed = true;

                        foreach (var data in testData)
                        {
                            var des = new DESAlgorithm();
                            des.Initialize(key);

                            byte[]? modeIv = (mode == CipherMode.ECB) ? null : iv;
                            var context = new CryptoContext(des, mode, PaddingMode.PKCS7, modeIv);

                            byte[] encrypted = context.Encrypt(data);
                            byte[] decrypted = context.Decrypt(encrypted);

                            bool success = data.SequenceEqual(decrypted.Take(data.Length).ToArray());
                            modePassed &= success;

                            if (!success)
                            {
                                Debug.WriteLine($"    FAIL: {mode} with {data.Length} bytes");
                                Debug.WriteLine($"      Original: {BitConverter.ToString(data)}");
                                Debug.WriteLine($"      Decrypted: {BitConverter.ToString(decrypted)}");
                            }
                        }

                        allTestsPassed &= modePassed;
                        Debug.WriteLine($"    {mode}: {(modePassed ? "PASS" : "FAIL")}");
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"    {mode}: ERROR - {ex.Message}");
                        allTestsPassed = false;
                    }
                }

                try
                {
                    Debug.WriteLine($"  Testing mode: PCBC");
                    var des = new DESAlgorithm();
                    des.Initialize(key);
                    var context = new CryptoContext(des, CipherMode.PCBC, PaddingMode.PKCS7, iv);

                    byte[] testDataPCBC = testData[0];
                    byte[] encrypted = context.Encrypt(testDataPCBC);
                    byte[] decrypted = context.Decrypt(encrypted);

                    bool success = testDataPCBC.SequenceEqual(decrypted);
                    allTestsPassed &= success;
                    Debug.WriteLine($"    PCBC: {(success ? "PASS" : "FAIL")}");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"    PCBC: ERROR - {ex.Message}");
                    allTestsPassed = false;
                }

                return allTestsPassed;
            });
        }
        #endregion

        #region 4. Тесты всех режимов набивки
        static async Task<bool> TestAllPaddingModes()
        {
            return await Task.Run(() =>
            {
                Debug.WriteLine("Testing all padding modes with various data lengths...");
                bool allTestsPassed = true;

                byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
                byte[] iv = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

                int[] testLengths = { 1, 7, 9, 15, 17, 23, 25, 31, 33, 100 };
                var paddingModes = Enum.GetValues(typeof(PaddingMode)).Cast<PaddingMode>();

                foreach (var paddingMode in paddingModes)
                {
                    Debug.WriteLine($"  Testing padding: {paddingMode}");
                    bool paddingPassed = true;

                    foreach (int length in testLengths)
                    {
                        try
                        {
                            byte[] testData = new byte[length];
                            new Random(length).NextBytes(testData);

                            var des = new DESAlgorithm();
                            des.Initialize(key);
                            var context = new CryptoContext(des, CipherMode.CBC, paddingMode, iv);

                            byte[] encrypted = context.Encrypt(testData);
                            byte[] decrypted = context.Decrypt(encrypted);

                            bool success = testData.SequenceEqual(decrypted);
                            paddingPassed &= success;

                            if (!success)
                            {
                                Debug.WriteLine($"    FAIL: {paddingMode} with {length} bytes");
                                Debug.WriteLine($"      Original length: {testData.Length}");
                                Debug.WriteLine($"      Decrypted length: {decrypted.Length}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"    ERROR: {paddingMode} with {length} bytes - {ex.Message}");
                            paddingPassed = false;
                        }
                    }

                    allTestsPassed &= paddingPassed;
                    Debug.WriteLine($"    {paddingMode}: {(paddingPassed ? "PASS" : "FAIL")}");
                }

                return allTestsPassed;
            });
        }
        #endregion

        #region 5. Тесты DEAL
        static async Task<bool> TestDEALComprehensive()
        {
            return await Task.Run(() =>
            {
                Debug.WriteLine("Testing DEAL algorithm with all key sizes and modes...");
                bool allTestsPassed = true;

                var keySizes = new[] { 16, 24, 32 }; 
                var testModes = new[] { CipherMode.ECB, CipherMode.CBC, CipherMode.CTR };

                foreach (int keySize in keySizes)
                {
                    Debug.WriteLine($"  Testing DEAL with {keySize * 8}-bit key");

                    foreach (var mode in testModes)
                    {
                        try
                        {
                            byte[] key = new byte[keySize];
                            byte[] iv = new byte[16];
                            byte[] testData = new byte[32];

                            new Random(keySize).NextBytes(key);
                            new Random(keySize + 1).NextBytes(iv);
                            new Random(keySize + 2).NextBytes(testData);

                            var deal = new DEALAlgorithm(keySize);
                            deal.Initialize(key);

                            byte[]? modeIv = (mode == CipherMode.ECB) ? null : iv;
                            var context = new CryptoContext(deal, mode, PaddingMode.PKCS7, modeIv);

                            byte[] encrypted = context.Encrypt(testData);
                            byte[] decrypted = context.Decrypt(encrypted);

                            bool success = testData.SequenceEqual(decrypted);
                            allTestsPassed &= success;

                            Debug.WriteLine($"    {mode}: {(success ? "PASS" : "FAIL")}");

                            if (!success)
                            {
                                Debug.WriteLine($"      Input length: {testData.Length}");
                                Debug.WriteLine($"      Output length: {decrypted.Length}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"    {mode}: ERROR - {ex.Message}");
                            allTestsPassed = false;
                        }
                    }
                }

                return allTestsPassed;
            });
        }
        #endregion

        #region 6. Тесты производительности
        static async Task<bool> TestPerformance()
        {
            return await Task.Run(() =>
            {
                Debug.WriteLine("Running performance tests...");
                bool allTestsPassed = true;

                byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
                byte[] iv = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

                var des = new DESAlgorithm();
                des.Initialize(key);
                var context = new CryptoContext(des, CipherMode.CBC, PaddingMode.PKCS7, iv);

                byte[] testData = new byte[100 * 1024];
                new Random(42).NextBytes(testData);

                var sw = Stopwatch.StartNew();
                byte[] encrypted = context.Encrypt(testData);
                byte[] decrypted = context.Decrypt(encrypted);
                sw.Stop();

                bool success = testData.SequenceEqual(decrypted);
                allTestsPassed &= success;

                Debug.WriteLine($"  Performance test (100KB): {(success ? "PASS" : "FAIL")}");
                Debug.WriteLine($"  Encryption/Decryption time: {sw.ElapsedMilliseconds}ms");
                Debug.WriteLine($"  Throughput: {(testData.Length * 2) / (sw.ElapsedMilliseconds / 1000.0) / 1024 / 1024:F2} MB/s");

                Debug.WriteLine("  Testing thread safety...");
                try
                {
                    var tasks = new List<Task>();
                    for (int i = 0; i < 5; i++)
                    {
                        int threadId = i;
                        tasks.Add(Task.Run(() =>
                        {
                            byte[] threadData = new byte[1024];
                            new Random(threadId).NextBytes(threadData);

                            var localDes = new DESAlgorithm();
                            localDes.Initialize(key);
                            var localContext = new CryptoContext(localDes, CipherMode.CBC, PaddingMode.PKCS7, iv);

                            byte[] localEncrypted = localContext.Encrypt(threadData);
                            byte[] localDecrypted = localContext.Decrypt(localEncrypted);

                            if (!threadData.SequenceEqual(localDecrypted))
                            {
                                throw new Exception($"Thread safety test failed in thread {threadId}");
                            }
                        }));
                    }

                    Task.WaitAll(tasks.ToArray());
                    Debug.WriteLine("  Thread safety: PASS");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"  Thread safety: FAIL - {ex.Message}");
                    allTestsPassed = false;
                }

                return allTestsPassed;
            });
        }
        #endregion

        #region 7. Тесты обработки файлов
        static async Task<bool> TestFileProcessing()
        {
            Debug.WriteLine("Testing file encryption/decryption with various file types...");
            bool allTestsPassed = true;

            byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] iv = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

            var des = new DESAlgorithm();
            des.Initialize(key);
            var context = new CryptoContext(des, CipherMode.CBC, PaddingMode.PKCS7, iv);

            try
            {
                // Тест 1: Текстовый файл
                string textFile = "test_text.txt";
                string textContent = "This is a comprehensive test of file encryption.\nLine 2: Testing various scenarios.\nLine 3: End of test data.";
                await File.WriteAllTextAsync(textFile, textContent);

                string encryptedTextFile = "test_text.enc";
                string decryptedTextFile = "test_text_decrypted.txt";

                await context.EncryptFileAsync(textFile, encryptedTextFile);
                await context.DecryptFileAsync(encryptedTextFile, decryptedTextFile);

                string originalText = await File.ReadAllTextAsync(textFile);
                string decryptedText = await File.ReadAllTextAsync(decryptedTextFile);
                bool textSuccess = originalText == decryptedText;
                allTestsPassed &= textSuccess;
                Debug.WriteLine($"  Text file test: {(textSuccess ? "PASS" : "FAIL")}");

                // Тест 2: Бинарный файл
                string binaryFile = "test_binary.bin";
                byte[] binaryData = new byte[8192];
                new Random(123).NextBytes(binaryData);
                await File.WriteAllBytesAsync(binaryFile, binaryData);

                string encryptedBinaryFile = "test_binary.enc";
                string decryptedBinaryFile = "test_binary_decrypted.bin";

                await context.EncryptFileAsync(binaryFile, encryptedBinaryFile);
                await context.DecryptFileAsync(encryptedBinaryFile, decryptedBinaryFile);

                byte[] originalBinary = await File.ReadAllBytesAsync(binaryFile);
                byte[] decryptedBinary = await File.ReadAllBytesAsync(decryptedBinaryFile);
                bool binarySuccess = originalBinary.SequenceEqual(decryptedBinary);
                allTestsPassed &= binarySuccess;
                Debug.WriteLine($"  Binary file test: {(binarySuccess ? "PASS" : "FAIL")}");

                // Тест 3: Пустой файл
                string emptyFile = "test_empty.txt";
                await File.WriteAllTextAsync(emptyFile, "");

                string encryptedEmptyFile = "test_empty.enc";
                string decryptedEmptyFile = "test_empty_decrypted.txt";

                await context.EncryptFileAsync(emptyFile, encryptedEmptyFile);
                await context.DecryptFileAsync(encryptedEmptyFile, decryptedEmptyFile);

                string originalEmpty = await File.ReadAllTextAsync(emptyFile);
                string decryptedEmpty = await File.ReadAllTextAsync(decryptedEmptyFile);
                bool emptySuccess = originalEmpty == decryptedEmpty;
                allTestsPassed &= emptySuccess;
                Debug.WriteLine($"  Empty file test: {(emptySuccess ? "PASS" : "FAIL")}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"  File processing test ERROR: {ex.Message}");
                allTestsPassed = false;
            }
            finally
            {
                string[] filesToDelete = {
                    "test_text.txt", "test_text.enc", "test_text_decrypted.txt",
                    "test_binary.bin", "test_binary.enc", "test_binary_decrypted.bin",
                    "test_empty.txt", "test_empty.enc", "test_empty_decrypted.txt"
                };

                foreach (string file in filesToDelete)
                {
                    try { if (File.Exists(file)) File.Delete(file); } catch { }
                }
            }

            return allTestsPassed;
        }
        #endregion

        #region 8. Тесты граничных случаев
        static async Task<bool> TestEdgeCases()
        {
            return await Task.Run(() =>
            {
                Debug.WriteLine("Testing edge cases and error conditions...");
                bool allTestsPassed = true;

                byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

                // Тест 1: Нулевые данные
                try
                {
                    var des = new DESAlgorithm();
                    des.Initialize(key);
                    var context = new CryptoContext(des, CipherMode.ECB, PaddingMode.PKCS7);

                    byte[] nullData = null!;
                    var result = context.Encrypt(nullData);
                    allTestsPassed = false;
                    Debug.WriteLine("  Null data test: FAIL (should have thrown exception)");
                }
                catch (ArgumentException ex) when (ex.Message.Contains("null", StringComparison.OrdinalIgnoreCase))
                {
                    Debug.WriteLine("  Null data test: PASS (ArgumentException as expected)");
                }
                catch (ArgumentNullException)
                {
                    Debug.WriteLine("  Null data test: PASS (ArgumentNullException as expected)");
                }
                catch (Exception ex)
                {
                    allTestsPassed = false;
                    Debug.WriteLine($"  Null data test: FAIL - Wrong exception: {ex.GetType().Name}: {ex.Message}");
                }

                // Тест 2: Пустые данные
                try
                {
                    var des = new DESAlgorithm();
                    des.Initialize(key);
                    var context = new CryptoContext(des, CipherMode.ECB, PaddingMode.PKCS7);

                    byte[] emptyData = Array.Empty<byte>();
                    byte[] encrypted = context.Encrypt(emptyData);
                    byte[] decrypted = context.Decrypt(encrypted);

                    bool success = emptyData.SequenceEqual(decrypted);
                    allTestsPassed &= success;
                    Debug.WriteLine($"  Empty data test: {(success ? "PASS" : "FAIL")}");
                }
                catch (Exception ex)
                {
                    allTestsPassed = false;
                    Debug.WriteLine($"  Empty data test: FAIL - {ex.Message}");
                }

                // Тест 3: Неправильный размер ключа для DES
                try
                {
                    var des = new DESAlgorithm();
                    byte[] wrongKey = { 0x01, 0x02, 0x03 };
                    des.Initialize(wrongKey);
                    allTestsPassed = false;
                    Debug.WriteLine("  Wrong key size test: FAIL (should have thrown exception)");
                }
                catch (ArgumentException)
                {
                    Debug.WriteLine("  Wrong key size test: PASS");
                }
                catch (Exception ex)
                {
                    allTestsPassed = false;
                    Debug.WriteLine($"  Wrong key size test: FAIL - {ex.Message}");
                }

                // Тест 4: Неправильный размер IV для CBC
                try
                {
                    var des = new DESAlgorithm();
                    des.Initialize(key);
                    byte[] wrongIv = { 0x01, 0x02, 0x03 };
                    var context = new CryptoContext(des, CipherMode.CBC, PaddingMode.PKCS7, wrongIv);
                    allTestsPassed = false;
                    Debug.WriteLine("  Wrong IV size test: FAIL (should have thrown exception)");
                }
                catch (ArgumentException)
                {
                    Debug.WriteLine("  Wrong IV size test: PASS");
                }
                catch (Exception ex)
                {
                    allTestsPassed = false;
                    Debug.WriteLine($"  Wrong IV size test: FAIL - {ex.Message}");
                }

                // Тест 5: Поврежденные зашифрованные данные
                try
                {
                    var des = new DESAlgorithm();
                    des.Initialize(key);
                    var context = new CryptoContext(des, CipherMode.ECB, PaddingMode.PKCS7);

                    byte[] validData = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
                    byte[] encrypted = context.Encrypt(validData);

                    encrypted[0] ^= 0xFF;

                    byte[] decrypted = context.Decrypt(encrypted);
                    Debug.WriteLine("  Corrupted data test: PASS (decryption completed)");

                    bool dataCorrupted = !validData.SequenceEqual(decrypted);
                    if (dataCorrupted)
                    {
                        Debug.WriteLine("  Data corruption verified: PASS");
                    }
                    else
                    {
                        Debug.WriteLine("  Data corruption verification: FAIL (data should be different)");
                        allTestsPassed = false;
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"  Corrupted data test: FAIL - {ex.Message}");
                    allTestsPassed = false;
                }

                return allTestsPassed;
            });
        }
        #endregion

        #region 9. Тестирование шифрования изображений 
        static async Task<bool> TestImageEncryption()
        {
            Debug.WriteLine("Testing image file encryption/decryption with source_image.png...");
            bool allTestsPassed = true;

            string imageFile = "source_image.png"; 

            string encryptedDesFile = "test_image_des.enc";
            string decryptedDesFile = "test_image_des_decrypted.png";
            string encryptedDealFile = "test_image_deal.enc";
            string decryptedDealFile = "test_image_deal_decrypted.png";

            try
            {
                if (!File.Exists(imageFile))
                {
                    Debug.WriteLine($"  ERROR: Image file '{imageFile}' not found in the Tests project directory!");
                    return false; 
                }

                byte[] originalImageData = await File.ReadAllBytesAsync(imageFile);
                Debug.WriteLine($"  Found PNG image - Size: {originalImageData.Length} bytes");

                bool isPng = originalImageData.Length >= 8 &&
                            originalImageData[0] == 0x89 && originalImageData[1] == 0x50 &&
                            originalImageData[2] == 0x4E && originalImageData[3] == 0x47 &&
                            originalImageData[4] == 0x0D && originalImageData[5] == 0x0A &&
                            originalImageData[6] == 0x1A && originalImageData[7] == 0x0A;

                Debug.WriteLine($"  Original file signature: {(isPng ? "VALID" : "INVALID")}");
                if (!isPng)
                {
                    Debug.WriteLine("  ERROR: The provided file is not a valid PNG image!");
                    return false; 
                }

                // Тест с DES
                byte[] desKey = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
                byte[] desIv = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

                var des = new DESAlgorithm();
                des.Initialize(desKey);
                var desContext = new CryptoContext(des, CipherMode.CBC, PaddingMode.PKCS7, desIv);

                await desContext.EncryptFileAsync(imageFile, encryptedDesFile);
                await desContext.DecryptFileAsync(encryptedDesFile, decryptedDesFile);

                byte[] desOriginal = await File.ReadAllBytesAsync(imageFile);
                byte[] desDecrypted = await File.ReadAllBytesAsync(decryptedDesFile);
                bool desSuccess = desOriginal.SequenceEqual(desDecrypted);
                allTestsPassed &= desSuccess; 
                Debug.WriteLine($"  DES image test: {(desSuccess ? "PASS" : "FAIL")}");
                if (!desSuccess)
                {
                    Debug.WriteLine($"    DES: Original and decrypted files differ. Original size: {desOriginal.Length}, Decrypted size: {desDecrypted.Length}");
                }

                // Тест с DEAL-128 
                byte[] dealKey = new byte[16];
                byte[] dealIv = new byte[16];
                new Random(42).NextBytes(dealKey);
                new Random(43).NextBytes(dealIv);

                var deal = new DEALAlgorithm(16);
                deal.Initialize(dealKey);
                var dealContext = new CryptoContext(deal, CipherMode.CBC, PaddingMode.PKCS7, dealIv);

                await dealContext.EncryptFileAsync(imageFile, encryptedDealFile);
                await dealContext.DecryptFileAsync(encryptedDealFile, decryptedDealFile);

                byte[] dealOriginal = await File.ReadAllBytesAsync(imageFile); 
                byte[] dealDecrypted = await File.ReadAllBytesAsync(decryptedDealFile);
                bool dealSuccess = dealOriginal.SequenceEqual(dealDecrypted);
                allTestsPassed &= dealSuccess; 
                Debug.WriteLine($"  DEAL-128 image test: {(dealSuccess ? "PASS" : "FAIL")}");
                if (!dealSuccess)
                {
                    Debug.WriteLine($"    DEAL: Original and decrypted files differ. Original size: {dealOriginal.Length}, Decrypted size: {dealDecrypted.Length}");
                }

                bool pngSignatureDes = desDecrypted.Length >= 8 &&
                            desDecrypted[0] == 0x89 && desDecrypted[1] == 0x50 &&
                            desDecrypted[2] == 0x4E && desDecrypted[3] == 0x47;

                bool pngSignatureDeal = dealDecrypted.Length >= 8 &&
                            dealDecrypted[0] == 0x89 && dealDecrypted[1] == 0x50 &&
                            dealDecrypted[2] == 0x4E && dealDecrypted[3] == 0x47;

                Debug.WriteLine($"  PNG signature after DES: {(pngSignatureDes ? "PASS" : "FAIL")}");
                Debug.WriteLine($"  PNG signature after DEAL: {(pngSignatureDeal ? "PASS" : "FAIL")}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"  Image processing test ERROR: {ex.Message}");
                Debug.WriteLine($"  Stack Trace: {ex.StackTrace}");
                allTestsPassed = false; 
            }
            finally
            {
                string[] filesToDelete = {
                    encryptedDesFile, decryptedDesFile,
                    encryptedDealFile, decryptedDealFile
                };

                foreach (string file in filesToDelete)
                {
                    try { if (File.Exists(file)) File.Delete(file); } catch (Exception e) { Debug.WriteLine($"Could not delete {file}: {e.Message}"); }
                }
            }

            Debug.WriteLine($"Image Encryption Test Final Result: {(allTestsPassed ? "PASS" : "FAIL")}");
            return allTestsPassed;
        }
        #endregion
    }
}