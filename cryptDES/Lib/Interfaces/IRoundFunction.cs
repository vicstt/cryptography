namespace cryptDES.Lib.Interfaces
{
    public interface IRoundFunction
    {
        /// <summary>
        /// Выполняет раундовую функцию.
        /// </summary>
        /// <param name="inputBlock">Входной блок данных для функции (обычно половина блока).</param>
        /// <param name="roundKey">Раундовый ключ.</param>
        /// <returns>Выходной блок данных после раундовой функции.</returns>
        byte[] ProcessRound(byte[] inputBlock, byte[] roundKey);
    }
}