using cryptRSA.Lib.RSA.Models;

namespace cryptRSA.Lib.RSA.Models
{
    /// <summary>
    /// Модель пары ключей RSA.
    /// </summary>
    public class KeyPair
    {
        public PublicKey PublicKey { get; }
        public PrivateKey PrivateKey { get; }

        public KeyPair(PublicKey publicKey, PrivateKey privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }
    }
}