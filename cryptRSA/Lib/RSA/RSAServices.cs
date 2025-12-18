using System.Numerics;
using cryptRSA.Lib.Interfaces;
using cryptRSA.Lib.Math;
using cryptRSA.Lib.RSA.Models;

namespace cryptRSA.Lib.RSA
{
    /// <summary>
    /// Основной сервис для работы с RSA.
    /// </summary>
    public class RSAServices : IServices
    {
        /// <summary>
        /// Перечисление типов тестов простоты, используемых при генерации ключей.
        /// </summary>
        public enum PrTestType
        {
            Fermat,
            SoloveyStrassen,
            MillerRabin
        }

        private readonly IMath _mathService;
        private readonly KeyGeneration _keyGenerator;

        public RSAServices(PrTestType testType, double minProbability, int bitLength)
        {
            _mathService = new CryptoMath();
            _keyGenerator = new KeyGeneration(testType, minProbability, bitLength, _mathService);
        }

        public BigInteger Encrypt(BigInteger message, PublicKey publicKey)
        {
            if (message >= publicKey.Modulus) throw new System.ArgumentException("Message is too large for the key modulus.");
            return _mathService.ModPow(message, publicKey.Exponent, publicKey.Modulus);
        }

        public BigInteger Decrypt(BigInteger ciphertext, PrivateKey privateKey)
        {
            if (ciphertext >= privateKey.Modulus) throw new System.ArgumentException("Ciphertext is too large for the key modulus.");
            return _mathService.ModPow(ciphertext, privateKey.Exponent, privateKey.Modulus);
        }

        public KeyPair GenerateKeyPair()
        {
            return _keyGenerator.GenerateNewKeyPair();
        }
    }
}