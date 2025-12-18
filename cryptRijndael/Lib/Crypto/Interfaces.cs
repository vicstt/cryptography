namespace Lib.Crypto
{
    public interface IBlockCipher
    {
        int BlockSize { get; }
        void Initialize(byte[] key);
        byte[] Encrypt(byte[] block);
        byte[] Decrypt(byte[] block);
    }

    public interface IBlockCipherMode
    {
        void Initialize(IBlockCipher cipher, byte[] iv);
        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);
    }

    public interface IPadding
    {
        byte[] Pad(byte[] data, int blockSize);
        byte[] Unpad(byte[] data);
    }
}