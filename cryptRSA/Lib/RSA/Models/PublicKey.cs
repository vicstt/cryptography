using System.Numerics;

namespace cryptRSA.Lib.RSA.Models
{
    /// <summary>
    /// Модель открытого ключа RSA.
    /// </summary>
    public class PublicKey
    {
        public BigInteger Exponent { get; }
        public BigInteger Modulus { get; }

        public PublicKey(BigInteger exponent, BigInteger modulus)
        {
            Exponent = exponent;
            Modulus = modulus;
        }
    }
}