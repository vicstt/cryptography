using cryptRSA.Lib.Attacks;
using cryptRSA.Lib.RSA.Models;

namespace cryptRSA.Lib.Interfaces
{
    /// <summary>
    /// Интерфейс для сервиса атаки Винера.
    /// </summary>
    public interface IWienersAttack
    {
        /// <summary>
        /// Выполняет атаку Винера на открытый ключ.
        /// </summary>
        WienersAttackModel PerformAttack(PublicKey publicKey);
    }
}