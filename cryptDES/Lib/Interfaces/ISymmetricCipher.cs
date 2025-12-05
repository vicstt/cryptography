namespace cryptDES.Lib.Interfaces
{
    public interface ISymmetricCipher
    {
        /// <summary>
        /// Инициализирует алгоритм с заданным ключом.
        /// </summary>
        /// <param name="key">Ключ шифрования.</param>
        void Initialize(byte[] key);

        /// <summary>
        /// Шифрует один блок данных.
        /// </summary>
        /// <param name="inputBlock">Входной блок данных.</param>
        /// <returns>Зашифрованный блок данных.</returns>
        byte[] EncryptBlock(byte[] inputBlock);

        /// <summary>
        /// Расшифровывает один блок данных.
        /// </summary>
        /// <param name="inputBlock">Входной блок данных.</param>
        /// <returns>Расшифрованный блок данных.</returns>
        byte[] DecryptBlock(byte[] inputBlock);

        /// <summary>
        /// Размер блока в байтах.
        /// </summary>
        int BlockSizeInBytes { get; }
    }
}