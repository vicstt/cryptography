using System;
using System.IO;
using System.Security.Cryptography;
using Lib.Crypto;
using Lib.FieldMath;
using Lib.RijndaelCipher;
using Lib.RijndaelCipher.Constants;
using Xunit;

namespace Tests
{
    public class RijndaelTests
    {
        [Fact]
        public void TestGF256_IrreduciblePolynomialsCount()
        {
            var gf = new GF256Service();
            
            var polys = gf.GetAllIrreducibleDegree8();
            
            Console.WriteLine($"Найдено {polys.Count} неприводимых полиномов степени 8:");
            foreach (var p in polys)
                Console.Write($"0x{p:X2} ");
            Console.WriteLine();
            
            Assert.Equal(30, polys.Count);
        }
        
        [Fact]
        public void TestGF256_AESModulusIsIrreducible()
        {
            var gf = new GF256Service();
            byte aesModulus = 0x1B; 
            
            bool isIrreducible = gf.IsIrreducible(aesModulus);
            
            Assert.True(isIrreducible);
        }
        
        [Fact]
        public void TestGF256_Addition()
        {
            var gf = new GF256Service();
            byte a = 0x57;
            byte b = 0x83;
            
            byte result = gf.Add(a, b);
            
            Assert.Equal((byte)(a ^ b), result);
        }
        
        [Fact]
        public void TestGF256_Multiplication()
        {
            var gf = new GF256Service();
            byte a = 0x57;
            byte b = 0x83;
            byte modulus = 0x1B;
            
            byte result = gf.Multiply(a, b, modulus);
            
            Assert.NotEqual(0, result);
        }
        
        [Fact]
        public void TestGF256_Inverse()
        {
            var gf = new GF256Service();
            byte a = 0x57;
            byte modulus = 0x1B;
            
            byte inverse = gf.Inverse(a, modulus);
            byte check = gf.Multiply(a, inverse, modulus);
            
            Assert.Equal(1, check);
        }
        
        [Fact]
        public void TestRijndael_EncryptionDecryption_128()
        {
            var gf = new GF256Service();
            byte modulus = 0x1B;
            
            byte[] data = new byte[16];
            RandomNumberGenerator.Create().GetBytes(data);
            
            byte[] key = new byte[16];
            RandomNumberGenerator.Create().GetBytes(key);
            
            var cipher = new RijndaelCipher(gf, BlockSize.Bits128, KeySize.Bits128, modulus);
            cipher.Initialize(key);
            
            byte[] encrypted = cipher.Encrypt(data);
            byte[] decrypted = cipher.Decrypt(encrypted);
            
            Assert.Equal(data, decrypted);
        }
        
        [Fact]
        public void TestRijndael_EncryptionDecryption_192()
        {
            var gf = new GF256Service();
            byte modulus = 0x1B;
            
            byte[] data = new byte[24];
            RandomNumberGenerator.Create().GetBytes(data);
            
            byte[] key = new byte[24];
            RandomNumberGenerator.Create().GetBytes(key);
            
            var cipher = new RijndaelCipher(gf, BlockSize.Bits192, KeySize.Bits192, modulus);
            cipher.Initialize(key);
            
            byte[] encrypted = cipher.Encrypt(data);
            byte[] decrypted = cipher.Decrypt(encrypted);
            
            Assert.Equal(data, decrypted);
        }
        
        [Fact]
        public void TestRijndael_EncryptionDecryption_256()
        {
            var gf = new GF256Service();
            byte modulus = 0x1B;
            
            byte[] data = new byte[32];
            RandomNumberGenerator.Create().GetBytes(data);
            
            byte[] key = new byte[32];
            RandomNumberGenerator.Create().GetBytes(key);
            
            var cipher = new RijndaelCipher(gf, BlockSize.Bits256, KeySize.Bits256, modulus);
            cipher.Initialize(key);
            
            byte[] encrypted = cipher.Encrypt(data);
            byte[] decrypted = cipher.Decrypt(encrypted);
            
            Assert.Equal(data, decrypted);
        }
        
        [Fact]
        public void TestRijndael_MixedSizes()
        {
            var gf = new GF256Service();
            byte modulus = 0x1B;
            
            byte[] data1 = new byte[16];
            byte[] key1 = new byte[32];
            RandomNumberGenerator.Create().GetBytes(data1);
            RandomNumberGenerator.Create().GetBytes(key1);
            
            var cipher1 = new RijndaelCipher(gf, BlockSize.Bits128, KeySize.Bits256, modulus);
            cipher1.Initialize(key1);
            
            byte[] encrypted1 = cipher1.Encrypt(data1);
            byte[] decrypted1 = cipher1.Decrypt(encrypted1);
            
            Assert.Equal(data1, decrypted1);
            
            byte[] data2 = new byte[32];
            byte[] key2 = new byte[16];
            RandomNumberGenerator.Create().GetBytes(data2);
            RandomNumberGenerator.Create().GetBytes(key2);
            
            var cipher2 = new RijndaelCipher(gf, BlockSize.Bits256, KeySize.Bits128, modulus);
            cipher2.Initialize(key2);
            
            byte[] encrypted2 = cipher2.Encrypt(data2);
            byte[] decrypted2 = cipher2.Decrypt(encrypted2);
            
            Assert.Equal(data2, decrypted2);
        }
        
        [Fact]
        public void TestCipherModes_ECB()
        {
            var gf = new GF256Service();
            byte modulus = 0x1B;
            
            byte[] data = new byte[64];
            RandomNumberGenerator.Create().GetBytes(data);
            
            byte[] key = new byte[16];
            RandomNumberGenerator.Create().GetBytes(key);
            
            var cipher = new RijndaelCipher(gf, BlockSize.Bits128, KeySize.Bits128, modulus);
            cipher.Initialize(key);
            
            var ecb = new ECBMode();
            ecb.Initialize(cipher, Array.Empty<byte>());
            
            byte[] encrypted = ecb.Encrypt(data);
            byte[] decrypted = ecb.Decrypt(encrypted);
            
            Assert.Equal(data, decrypted);
        }
        
        [Fact]
        public void TestCipherModes_CBC()
        {
            var gf = new GF256Service();
            byte modulus = 0x1B;
            
            byte[] data = new byte[64];
            RandomNumberGenerator.Create().GetBytes(data);
            
            byte[] key = new byte[16];
            RandomNumberGenerator.Create().GetBytes(key);
            
            var cipher = new RijndaelCipher(gf, BlockSize.Bits128, KeySize.Bits128, modulus);
            cipher.Initialize(key);
            
            var cbc = new CBCMode();
            byte[] iv = new byte[16];
            RandomNumberGenerator.Create().GetBytes(iv);
            cbc.Initialize(cipher, iv);
            
            byte[] encrypted = cbc.Encrypt(data);
            byte[] decrypted = cbc.Decrypt(encrypted);
            
            Assert.Equal(data, decrypted);
        }
        
        [Fact]
        public void TestPadding_PKCS7()
        {
            var padding = new PKCS7Padding();
            byte[] data = new byte[10];
            RandomNumberGenerator.Create().GetBytes(data);
            int blockSize = 16;
            
            byte[] padded = padding.Pad(data, blockSize);
            byte[] unpadded = padding.Unpad(padded);
            
            Assert.Equal(data, unpadded);
            Assert.Equal(0, padded.Length % blockSize);
        }
        
        [Fact]
        public void TestFileEncryption()
        {
            string testFile = "testfile.txt";
            string content = "Test file encryption with Rijndael\n" +
                           "Тестирование шифрования файлов\n" +
                           "1234567890";
            File.WriteAllText(testFile, content);
            
            byte[] fileData = File.ReadAllBytes(testFile);
            
            var gf = new GF256Service();
            byte modulus = 0x1B;
            
            byte[] key = new byte[32];
            RandomNumberGenerator.Create().GetBytes(key);
            
            var cipher = new RijndaelCipher(gf, BlockSize.Bits128, KeySize.Bits256, modulus);
            cipher.Initialize(key);
            
            var cbc = new CBCMode();
            byte[] iv = new byte[16];
            RandomNumberGenerator.Create().GetBytes(iv);
            cbc.Initialize(cipher, iv);
            
            var padding = new PKCS7Padding();
            byte[] padded = padding.Pad(fileData, 16);
            
            byte[] encrypted = cbc.Encrypt(padded);
            File.WriteAllBytes(testFile + ".enc", encrypted);
            
            byte[] decrypted = cbc.Decrypt(encrypted);
            byte[] unpadded = padding.Unpad(decrypted);
            
            File.WriteAllBytes(testFile + ".dec", unpadded);
            
            Assert.Equal(fileData, unpadded);
            
            File.Delete(testFile);
            File.Delete(testFile + ".enc");
            File.Delete(testFile + ".dec");
        }
        
        [Fact]
        public void TestImageEncryptionAsBinary()
        {
            string binFile = "test_image.bin";
            byte[] imageData = new byte[1024];
            for (int i = 0; i < imageData.Length; i++)
                imageData[i] = (byte)(i % 256);
            
            File.WriteAllBytes(binFile, imageData);
            
            var gf = new GF256Service();
            byte modulus = 0x1B;
            
            byte[] key = new byte[16];
            RandomNumberGenerator.Create().GetBytes(key);
            
            var cipher = new RijndaelCipher(gf, BlockSize.Bits128, KeySize.Bits128, modulus);
            cipher.Initialize(key);
            
            var ecb = new ECBMode();
            ecb.Initialize(cipher, Array.Empty<byte>());
            
            var padding = new ZeroPadding();
            byte[] padded = padding.Pad(imageData, 16);
            
            byte[] encrypted = ecb.Encrypt(padded);
            byte[] decrypted = ecb.Decrypt(encrypted);
            byte[] unpadded = padding.Unpad(decrypted);
            
            File.WriteAllBytes(binFile + ".enc", encrypted);
            File.WriteAllBytes(binFile + ".dec", unpadded);
            
            Assert.Equal(imageData, unpadded);
            
            File.Delete(binFile);
            File.Delete(binFile + ".enc");
            File.Delete(binFile + ".dec");
        }
        
        [Fact]
        public void TestImageEncryption_ImagePNG()
        {
            Console.WriteLine("\n=== Тест шифрования изображения image.png ===");
            
            string imagePath = "image.png";
            
            if (!File.Exists(imagePath))
            {
                Console.WriteLine($"Файл {imagePath} не найден. Тест пропущен.");
                Console.WriteLine("Положите файл image.png в папку Tests для выполнения теста.");
                return; 
            }
            
            byte[] originalData = File.ReadAllBytes(imagePath);
            long fileSize = originalData.Length;
            Console.WriteLine($"Файл: {imagePath}");
            Console.WriteLine($"Размер: {fileSize} байт ({fileSize / 1024.0:F2} KB)");
            
            var gf = new GF256Service();
            byte modulus = 0x1B; 
            
            byte[] key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(key);
            
            var cipher = new RijndaelCipher(gf, BlockSize.Bits128, KeySize.Bits256, modulus);
            cipher.Initialize(key);
            
            var cbc = new CBCMode();
            byte[] iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(iv);
            cbc.Initialize(cipher, iv);
            
            var padding = new PKCS7Padding();
            
            Console.WriteLine("Шифруем файл...");
            byte[] padded = padding.Pad(originalData, 16);
            byte[] encrypted = cbc.Encrypt(padded);
            
            string encryptedFile = "image.png.encrypted";
            File.WriteAllBytes(encryptedFile, encrypted);
            Console.WriteLine($"Зашифрованный файл создан: {encryptedFile}");
            Console.WriteLine($"Размер зашифрованного: {encrypted.Length} байт");
            
            Console.WriteLine("Дешифруем файл...");
            byte[] decrypted = cbc.Decrypt(encrypted);
            byte[] unpadded = padding.Unpad(decrypted);
            
            string decryptedFile = "image.png.decrypted";
            File.WriteAllBytes(decryptedFile, unpadded);
            Console.WriteLine($"Дешифрованный файл создан: {decryptedFile}");
            
            Assert.Equal(originalData.Length, unpadded.Length);
            
            bool filesMatch = true;
            int mismatchIndex = -1;
            for (int i = 0; i < originalData.Length; i++)
            {
                if (originalData[i] != unpadded[i])
                {
                    filesMatch = false;
                    mismatchIndex = i;
                    break;
                }
            }
            
            if (filesMatch)
            {
                Console.WriteLine("Файл успешно зашифрован и дешифрован");
                Console.WriteLine("Дешифрованный файл идентичен оригиналу");
                
                if (unpadded.Length >= 8)
                {
                    bool isPNG = unpadded[0] == 0x89 && 
                                 unpadded[1] == 0x50 && 
                                 unpadded[2] == 0x4E && 
                                 unpadded[3] == 0x47 &&
                                 unpadded[4] == 0x0D && 
                                 unpadded[5] == 0x0A && 
                                 unpadded[6] == 0x1A && 
                                 unpadded[7] == 0x0A;
                    
                    if (isPNG)
                        Console.WriteLine("Дешифрованный файл имеет корректную сигнатуру PNG");
                    else
                        Console.WriteLine("Дешифрованный файл не имеет сигнатуру PNG (может быть поврежден)");
                }
            }
            else
            {
                Console.WriteLine($"Ошибка: файлы не совпадают на байте {mismatchIndex}");
                Console.WriteLine($"  Оригинал: 0x{originalData[mismatchIndex]:X2}");
                Console.WriteLine($"  Дешифр:   0x{unpadded[mismatchIndex]:X2}");
            }
            
            Assert.True(filesMatch, "Дешифрованный файл не совпадает с оригиналом");
            
            Console.WriteLine("\nДополнительные проверки");
            
            Console.WriteLine("1. Тестируем ECB режим...");
            var ecb = new ECBMode();
            ecb.Initialize(cipher, Array.Empty<byte>());
            
            byte[] encryptedEcb = ecb.Encrypt(padded);
            byte[] decryptedEcb = ecb.Decrypt(encryptedEcb);
            byte[] unpaddedEcb = padding.Unpad(decryptedEcb);
            
            bool ecbOk = originalData.Length == unpaddedEcb.Length;
            for (int i = 0; i < originalData.Length && ecbOk; i++)
                if (originalData[i] != unpaddedEcb[i]) ecbOk = false;
            
            Console.WriteLine($"   ECB режим: {(ecbOk ? "✓" : "✗")}");
            
            Console.WriteLine("2. Тестируем с другим неприводимым полиномом...");
            var polys = gf.GetAllIrreducibleDegree8();
            if (polys.Count > 1 && polys[1] != modulus)
            {
                byte altModulus = polys[1];
                var cipher2 = new RijndaelCipher(gf, BlockSize.Bits128, KeySize.Bits128, altModulus);
                cipher2.Initialize(key[..16]);
                
                var ecb2 = new ECBMode();
                ecb2.Initialize(cipher2, Array.Empty<byte>());
                
                byte[] encryptedAlt = ecb2.Encrypt(padded);
                byte[] decryptedAlt = ecb2.Decrypt(encryptedAlt);
                byte[] unpaddedAlt = padding.Unpad(decryptedAlt);
                
                bool altOk = originalData.Length == unpaddedAlt.Length;
                for (int i = 0; i < originalData.Length && altOk; i++)
                    if (originalData[i] != unpaddedAlt[i]) altOk = false;
                
                Console.WriteLine($"   Модуль 0x{altModulus:X2}: {(altOk ? "✓" : "✗")}");
            }
            
            // 3. Статистика
            Console.WriteLine("\nСтатистика");
            Console.WriteLine($"Оригинальный размер: {fileSize} байт");
            Console.WriteLine($"Размер с padding: {padded.Length} байт (+{padded.Length - fileSize} байт)");
            Console.WriteLine($"Зашифрованный размер: {encrypted.Length} байт");
            Console.WriteLine($"Коэффициент расширения: {(double)encrypted.Length / fileSize:F3}");;
            
            Console.WriteLine("Тест завершен");
        }
    }
}