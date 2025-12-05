namespace cryptDES.Lib.Interfaces
{
    public interface IKeyScheduler
    {
        /// <summary>
        /// Генерирует массив раундовых ключей из входного ключа.
        /// </summary>
        /// <param name="key">Входной ключ.</param>
        /// <returns>Массив раундовых ключей.</returns>
        byte[][] GenerateRoundKeys(byte[] key);
    }
}