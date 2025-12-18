using System.Numerics;
using cryptRSA.Lib.RSA.Models;

namespace cryptRSA.Lib.Interfaces
{
    /// <summary>
    /// Интерфейс для сервиса RSA.
    /// </summary>
    public interface IServices
    {
        /// <summary>
        /// Шифрует сообщение.
        /// </summary>
        BigInteger Encrypt(BigInteger message, PublicKey publicKey);

        /// <summary>
        /// Дешифрует шифротекст.
        /// </summary>
        BigInteger Decrypt(BigInteger ciphertext, PrivateKey privateKey);

        /// <summary>
        /// Генерирует новую пару ключей.
        /// </summary>
        KeyPair GenerateKeyPair();
    }
}