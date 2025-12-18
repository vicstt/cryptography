using System.Numerics;

namespace cryptRSA.Lib.RSA.Models
{
    /// <summary>
    /// Модель закрытого ключа RSA.
    /// </summary>
    public class PrivateKey
    {
        public BigInteger Exponent { get; }
        public BigInteger Modulus { get; }

        public PrivateKey(BigInteger exponent, BigInteger modulus)
        {
            Exponent = exponent;
            Modulus = modulus;
        }
    }
}