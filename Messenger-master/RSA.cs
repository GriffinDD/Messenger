//author: Griffin Danner-Doran
//This file contains the RSA class, which has various functions for generating, writing, reading, and using RSA keys.


using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Messenger;

using PrimeFinder;

/// <summary>
/// This class contains functions for generating an RSA key pair of a given size, writing or reading the public/private
/// key from a given file, and RSA encrypting/decryting a message using a provided key file.
/// </summary>
public class RSA
{
    /// <summary>
    /// This class creates a public/private key pair of the provided size using the RSA algorithm, then writes the keys
    /// in a Base64 encoded format to their respective files. The component primes are generated using a PrimeGenerator
    /// instance.
    /// </summary>
    /// <param name="keySize">The size in bits of n, the combined key derived from 2 large primes.</param>
    public void GenerateKeys(int keySize)
    {
        //pick a semi-random size for p
        var pSize = keySize / 2;
        var offset = pSize * RandomNumberGenerator.GetInt32(20, 31) / (double)100;
        if (RandomNumberGenerator.GetInt32(0, 2) == 0) offset *= -1;
        pSize += (int)offset;

        //round down to the nearest byte
        pSize -= pSize % 8;

        var gen = new PrimeGenerator();
        var p = gen.GeneratePrimes(pSize / 8);
        //q's size is the difference between p and keySize
        var q = gen.GeneratePrimes((keySize - pSize) / 8);
        var N = p * q;
        var r = (p - 1) * (q - 1);
        BigInteger E = 65537;
        var D = modInverse(E, r);
        //write the encoded keys to their respective files
        WriteKeyToFile(E, N, true);
        WriteKeyToFile(D, N, false);
    }

    /// <summary>
    /// This private method is used to write public or private keys in their Base64 encoded form.
    /// </summary>
    /// <param name="keyValue">The exponent component of the key, either E or D.</param>
    /// <param name="mod">The shared modulus of the keys, N.</param>
    /// <param name="publicKey">True if we are storing a public key, false for a private key.</param>
    private void WriteKeyToFile(BigInteger keyValue, BigInteger mod, bool publicKey)
    {
        var f = publicKey ? new FileInfo("public.key") : new FileInfo("private.key");
        var fileWriter = new StreamWriter(f.Create());
        var k = keyValue.GetByteCount();
        var n = mod.GetByteCount();
        var kBytes = BitConverter.GetBytes(k);
        Array.Reverse(kBytes);
        var nBytes = BitConverter.GetBytes(n);
        Array.Reverse(nBytes);
        var KBytes = keyValue.ToByteArray();
        var NBytes = mod.ToByteArray();
        var keyBytes = new Byte[8 + k + n];
        kBytes.CopyTo(keyBytes, 0);
        KBytes.CopyTo(keyBytes, 4);
        nBytes.CopyTo(keyBytes, 4 + k);
        NBytes.CopyTo(keyBytes, 8 + k);
        var key = Convert.ToBase64String(keyBytes);
        //Use the JSON format corresponding to our key type.
        string keyJson;
        if (publicKey)
        {
            var p = new PublicKey
            {
                email = string.Empty,
                key = key
            };
            keyJson = JsonConvert.SerializeObject(p);
        }
        else
        {
            var p = new PrivateKey
            {
                email = new List<string> { },
                key = key
            };
            keyJson = JsonConvert.SerializeObject(p);
        }

        fileWriter.WriteLine(keyJson);
        fileWriter.Close();
    }

    /// <summary>
    /// This private method is used to read public and private keys when they are needed for encryption or decryption.
    /// </summary>
    /// <param name="keyFile">The key file to extract our key from.</param>
    /// <param name="publicKey">True if we are extracting a public key, false for a private key.</param>
    /// <returns> BigIntegers (Exponent, Modulus) where Exponent is E or D and Modulus is N.</returns>
    private (BigInteger, BigInteger) ReadKeyFromFile(string keyFile, bool publicKey)
    {
        var f = new FileInfo(keyFile);
        var fileReader = new StreamReader(f.OpenRead());
        var keyJson = fileReader.ReadToEnd();
        fileReader.Close();
        byte[] keyBytes;
        if (publicKey)
        {
            var key = JsonConvert.DeserializeObject<PublicKey>(keyJson);
            keyBytes = Convert.FromBase64String(key!.key);
        }
        else
        {
            var key = JsonConvert.DeserializeObject<PrivateKey>(keyJson);
            keyBytes = Convert.FromBase64String(key!.key);
        }

        var kBytes = new[] { keyBytes[0], keyBytes[1], keyBytes[2], keyBytes[3] };
        //reverse since it is big endian
        Array.Reverse(kBytes);
        var k = BitConverter.ToInt32(kBytes, 0);
        var KBytes = new Byte[k];
        for (int i = 0; i < k; i++)
        {
            KBytes[i] = keyBytes[i + 4];
        }

        var K = new BigInteger(KBytes);
        var nBytes = new[] { keyBytes[4 + k], keyBytes[4 + k + 1], keyBytes[4 + k + 2], keyBytes[4 + k + 3] };
        Array.Reverse(nBytes);
        var n = BitConverter.ToInt32(nBytes, 0);
        var NBytes = new Byte[n];
        for (int i = 0; i < n; i++)
        {
            NBytes[i] = keyBytes[i + k + 8];
        }

        var N = new BigInteger(NBytes);
        return (K, N);
    }

    /// <summary>
    /// This method extracts the key from the provided file and uses it to RSA encrypt the message then returns the
    /// resulting ciphertext.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <param name="keyFile">The location of the public key to use for encryption.</param>
    /// <returns>The ciphertext string resulting from the encryption.</returns>
    public string EncryptMessage(string plaintext, string keyFile)
    {
        var messageBytes = Encoding.ASCII.GetBytes(plaintext);
        var messageInt = new BigInteger(messageBytes);
        var publicKey = ReadKeyFromFile(keyFile, true);
        messageInt = BigInteger.ModPow(messageInt, publicKey.Item1, publicKey.Item2);
        messageBytes = messageInt.ToByteArray();
        var ciphertext = Convert.ToBase64String(messageBytes);
        return ciphertext;
    }

    /// <summary>
    /// This method extracts the local private key from the "private.key" file and uses it to RSA decrypt the given
    /// ciphertext then returns the resulting plaintext.
    /// </summary>
    /// <param name="ciphertext">The RSA encrypted message to decrypt.</param>
    /// <returns>The plaintext string resulting from the decryption.</returns>
    public string DecryptMessage(string ciphertext)
    {
        var messageBytes = Convert.FromBase64String(ciphertext);
        var messageInt = new BigInteger(messageBytes);
        //always read from "private.key" for any incoming messages
        var privateKey = ReadKeyFromFile("private.key", false);
        messageInt = BigInteger.ModPow(messageInt, privateKey.Item1, privateKey.Item2);
        messageBytes = messageInt.ToByteArray();
        var plaintext = Encoding.ASCII.GetString(messageBytes);
        return plaintext;
    }

    /// <summary>
    /// This method finds and returns the multiplicative inverse of a under mod m.
    /// </summary>
    /// <param name="a">The value for which to find the multiplicative inverse of.</param>
    /// <param name="n">The modulus over which the multiplicative inverse is found.</param>
    /// <returns>The BigInteger representing the multiplicative inverse of a over mod n. </returns>
    private static BigInteger modInverse(BigInteger a, BigInteger n)
    {
        BigInteger i = n, v = 0, d = 1;
        while (a > 0)
        {
            BigInteger t = i / a, x = a;
            a = i % x;
            i = x;
            x = d;
            d = v - t * x;
            v = x;
        }

        v %= n;
        if (v < 0) v = (v + n) % n;
        return v;
    }
}