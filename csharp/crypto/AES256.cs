using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace EncryptionDemo
{
	public class AES256
	{
		public AES256 ()
		{
		}
		
		public static byte[] Encrypt(byte[] data, byte[] key)
		{
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			rijndaelManaged.Mode = CipherMode.CBC;
			rijndaelManaged.Padding = PaddingMode.PKCS7;
			rijndaelManaged.KeySize = 256;
			rijndaelManaged.BlockSize = 256;
			rijndaelManaged.Key = key;
			rijndaelManaged.IV = key;
			
			ICryptoTransform Encryptor = rijndaelManaged.CreateEncryptor(rijndaelManaged.Key, rijndaelManaged.IV);
			
			MemoryStream MemStream = new MemoryStream();
			CryptoStream CryptoStream = new CryptoStream(MemStream, Encryptor, CryptoStreamMode.Write);
			CryptoStream.Write(data, 0, data.Length);
			CryptoStream.FlushFinalBlock();
			
			byte[] returnValue = MemStream.ToArray();
	
			MemStream.Close();
			CryptoStream.Close();
			rijndaelManaged.Clear();
			
			return returnValue;
	     }
	 
		public static byte[] Decrypt(byte[] data, byte[] key)
		{
			RijndaelManaged rijndaelManaged = new RijndaelManaged();
			rijndaelManaged.Mode = CipherMode.CBC;
			rijndaelManaged.Padding = PaddingMode.PKCS7;
			rijndaelManaged.KeySize = 256;
			rijndaelManaged.BlockSize = 256;
			rijndaelManaged.Key = key;
			rijndaelManaged.IV = key;
			
			byte[] returnValue = new byte[data.Length];
			ICryptoTransform Decryptor = rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV);
			
			MemoryStream MemStream = new MemoryStream(data);
			CryptoStream CryptoStream = new CryptoStream(MemStream, Decryptor, CryptoStreamMode.Read);
			CryptoStream.Read(returnValue, 0, returnValue.Length);
			
			MemStream.Close();	 
			CryptoStream.Close();
			rijndaelManaged.Clear();
			
			return returnValue;
	     }
	}
}