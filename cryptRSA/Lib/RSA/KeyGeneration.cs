using System;
using System.Numerics;
using cryptRSA.Lib.Interfaces;
using cryptRSA.Lib.Primes;
using cryptRSA.Lib.RSA.Models;

namespace cryptRSA.Lib.RSA
{
    /// <summary>
    /// Вложенный сервис для генерации ключей RSA.
    /// </summary>
    public class KeyGeneration
    {
        private readonly IPrimalityTests _primalityTest;
        private readonly double _minProbability;
        private readonly int _bitLength;
        private readonly IMath _mathService;
        private readonly Random _random = new Random();

        public KeyGeneration(RSAServices.PrTestType testType, double minProbability, int bitLength, IMath mathService)
        {
            _minProbability = minProbability;
            _bitLength = bitLength;
            _mathService = mathService;

            _primalityTest = testType switch
            {
                RSAServices.PrTestType.Fermat => new FermatTest(mathService),
                RSAServices.PrTestType.SoloveyStrassen => new SoloveyStrassenTest(mathService),
                RSAServices.PrTestType.MillerRabin => new MillerRabinTest(mathService),
                _ => throw new ArgumentException("Invalid test type.")
            };
        }

        public KeyPair GenerateNewKeyPair()
        {
            BigInteger p, q, n, phi, e, d;

            // Вычисляем минимальную разность для защиты от атаки Ферма
            int minDiffBits = System.Math.Max(10, _bitLength / 4);
            BigInteger minDifference = BigInteger.One << minDiffBits;

            do
            {
                p = GeneratePrime();
                q = GeneratePrime();
                n = p * q;

                // Проверка на атаку Ферма: |p - q| должно быть достаточно большим
            } while (BigInteger.Abs(p - q) < minDifference);

            phi = (p - 1) * (q - 1);
            e = 65537; // Стандартный выбор

            // Если e и phi не взаимно просты, выбираем другое e
            if (_mathService.Gcd(e, phi) != 1)
            {
                e = FindPublicExponent(phi);
            }

            // Находим d: e * d ≡ 1 (mod phi)
            var (_, x, _) = _mathService.ExtendedGcd(e, phi);
            d = (x % phi + phi) % phi; // Делаем d положительным

            // Проверка на атаку Винера: d > n^(1/4)/3
            var nSqrt = Sqrt(n);
            var nFourthRoot = Sqrt(nSqrt);
            var threshold = nFourthRoot / 3;
            
            if (d < threshold)
            {
                // Если d слишком мал, генерируем заново
                return GenerateNewKeyPair();
            }

            var publicKey = new PublicKey(e, n);
            var privateKey = new PrivateKey(d, n);
            return new KeyPair(publicKey, privateKey);
        }

        private BigInteger GeneratePrime()
        {
            BigInteger candidate;
            int attempts = 0;
            const int maxAttempts = 1000;

            do
            {
                attempts++;
                if (attempts > maxAttempts)
                    throw new InvalidOperationException($"Не удалось сгенерировать простое число после {maxAttempts} попыток");

                candidate = GenerateRandomBigInteger(_bitLength / 2);
                if (candidate.IsEven) candidate += 1;

            } while (!_primalityTest.IsPrime(candidate, _minProbability));

            return candidate;
        }

        private BigInteger FindPublicExponent(BigInteger phi)
        {
            BigInteger[] commonEs = { 65537, 17, 3, 5, 7, 11, 13, 19, 23, 29, 31 };
            
            foreach (var testE in commonEs)
            {
                if (testE < phi && _mathService.Gcd(testE, phi) == 1)
                {
                    return testE;
                }
            }
            
            for (BigInteger testE = 3; testE < 1000; testE += 2)
            {
                if (testE < phi && _mathService.Gcd(testE, phi) == 1)
                {
                    return testE;
                }
            }
            
            throw new InvalidOperationException($"Не удалось найти e, взаимно простое с φ={phi}");
        }

        private BigInteger GenerateRandomBigInteger(int bitLength)
        {
            if (bitLength < 8)
                bitLength = 8;
            
            int byteCount = (bitLength + 7) / 8;
            
            byte[] bytes = new byte[byteCount];
            _random.NextBytes(bytes);
            
            int bitsInLastByte = bitLength % 8;
            if (bitsInLastByte == 0) bitsInLastByte = 8;
            
            byte msbMask = (byte)(1 << (bitsInLastByte - 1));
            bytes[byteCount - 1] |= msbMask;
            
            byte clearMask = (byte)((1 << bitsInLastByte) - 1);
            bytes[byteCount - 1] &= clearMask;
            
            bytes[0] |= 0x01;
            
            BigInteger result = new BigInteger(bytes, isUnsigned: true);
            
            BigInteger minValue = BigInteger.One << (bitLength - 1);
            BigInteger maxValue = (BigInteger.One << bitLength) - BigInteger.One;
            
            if (result < minValue || result > maxValue)
            {
                return GenerateRandomBigInteger(bitLength);
            }
            
            return result;
        }

        private BigInteger Sqrt(BigInteger n)
        {
            if (n < 0) return 0;
            if (n == 0) return 0;
            
            BigInteger x = n;
            BigInteger y = (n + 1) / 2;
            while (y < x)
            {
                x = y;
                y = (x + n / x) / 2;
            }
            return x;
        }
    }
}