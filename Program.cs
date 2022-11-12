/*
* MIT License
* 
* Copyright (c) 2022 FZFalzar
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

using System;
using System.Security.Cryptography;
using System.IO;
using System.Linq;

namespace NikkeTools
{
    class Program
    {
        internal class Header
        {
            public byte[] MAGIC { get; set; }
            public uint Version { get; set; }
            public short HeaderSize { get; set; }
            public short EncryptionMode { get; set; }
            public short KeyLength { get; set; }
            public short EncryptedLength { get; set; }

            public byte[] Key { get; set; }
            public byte[] IV { get; set; }

            public override string ToString()
            {
                return $"Version: {Version:X2}\nHeaderSize: {HeaderSize:X2}\nEncryptionMode: {EncryptionMode:X2}\nKeyLength: {KeyLength:X2}\nEncryptedLength: {EncryptedLength:X2}";
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine("NIKKE EB Asset Encryptor/Decryptor");
            Usage();

            // try all files instead of just *.bundle
            foreach (var path in Directory.GetFiles(args[0]))
            {
                if(path.EndsWith("_MOD")) EncryptBundleV1(path);
                else DecryptBundle(path);
            }
        }
        
        static void Usage()
        {
            Console.WriteLine();
            Console.WriteLine("Usage: Drag drop folder onto exe for default decryption mode");
            Console.WriteLine("To encrypt, append _MOD to the modded assetbundle file name, then drag drop folder containing mod.");
            Console.WriteLine("After encryption, a new file with _MOD_ENC will be created, strip this and replace file in /eb");
            Console.WriteLine();
        }

        static void EncryptBundleV1(string path)
        {
            byte[] input = null;
            try
            {
                input = File.ReadAllBytes(path);
            } 
            catch(Exception e)
            {
                Console.WriteLine($"Error reading from {path}");
                Console.WriteLine(e.ToString());
            }

            try
            {

                using (MemoryStream ms = new MemoryStream())
                using (BinaryWriter writer = new BinaryWriter(ms))
                {
                    var sha = SHA256.Create();
                    var inputHash = sha.ComputeHash(input);

                    Header header = new Header();
                    header.Key = System.Text.Encoding.UTF8.GetBytes("ModdedNIKKEAsset");
                    header.IV = inputHash.AsSpan(0, 16).ToArray();

                    header.MAGIC = new byte[] { 0x4e, 0x4b, 0x41, 0x42 };
                    header.Version = 1;

                    // magic(0x4) + ver(0x4) + fields(0x2 * 4) + key(0x10) + IV(0x10)
                    header.HeaderSize = 48;                         // field 1
                    header.EncryptionMode = 0;                      // field 2
                    header.KeyLength = (short)header.Key.Length;    // field 3
                    header.EncryptedLength = 128;                   // field 4

                    // write header size, encryption mode, key length, encrypted length
                    var keyHash = sha.ComputeHash(header.Key);
                    var headerSlice = input.AsSpan(0, header.EncryptedLength).ToArray();

                    // encrypt
                    Aes aes = Aes.Create();
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.None;
                    var encryptor = aes.CreateEncryptor(keyHash, header.IV);
                    var encrypted = encryptor.TransformFinalBlock(headerSlice, 0, headerSlice.Length);

                    // write header
                    writer.Write(header.MAGIC);
                    writer.Write(header.Version);
                    writer.Write((short)(header.HeaderSize - 100));
                    writer.Write((short)(header.EncryptionMode - 100));
                    writer.Write((short)(header.KeyLength - 100));
                    writer.Write((short)(header.EncryptedLength - 100));
                    writer.Write(header.Key);
                    writer.Write(header.IV);

                    // write encrypted contents
                    writer.Write(encrypted);

                    // write remainder
                    writer.Write(input.AsSpan(header.EncryptedLength));

                    // end
                    using (FileStream fs = new FileStream(path + "_ENC", FileMode.OpenOrCreate))
                    {
                        fs.Write(ms.GetBuffer());
                    }
                    Console.WriteLine($"Processed: {path + "_ENC"}");
                }
            } 
            catch (Exception e)
            {
                Console.WriteLine("Error processing file: ");
                Console.WriteLine(e.ToString());
            }
        }

        static void DecryptBundle(string path)
        {
            byte[] headermagic = new byte[] {
                0x4e, 0x4b, 0x41, 0x42
            };
            try
            {
                byte[] input = File.ReadAllBytes(path);

                using (MemoryStream ms = new MemoryStream(input))
                using (BinaryReader reader = new BinaryReader(ms))
                {
                    Header header = new Header();
                    header.MAGIC = reader.ReadBytes(4);
                    if (!header.MAGIC.SequenceEqual(headermagic)) 
                        throw new FileLoadException("Not NKAB!");

                    header.Version = reader.ReadUInt32();
                    header.HeaderSize = (short)(reader.ReadInt16() + 100);
                    header.EncryptionMode = (short)(reader.ReadInt16() + 100);
                    header.KeyLength = (short)(reader.ReadInt16() + 100);
                    header.EncryptedLength = (short)(reader.ReadInt16() + 100);

                    header.Key = reader.ReadBytes(header.KeyLength);
                    header.IV = reader.ReadBytes(header.KeyLength);

                    var sha = SHA256.Create();
                    var hashed = sha.ComputeHash(header.Key);

                    var encrypted = reader.ReadBytes(header.EncryptedLength);
                    Aes aes = Aes.Create();
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.None;
                    var decryptor = aes.CreateDecryptor(hashed, header.IV);
                    byte[] outBuf = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
                    byte[] remainderBuf = input.AsSpan((int)reader.BaseStream.Position).ToArray();
                    using (FileStream fs = new FileStream(path + "_dec.bundle", FileMode.OpenOrCreate))
                    {
                        fs.Write(outBuf);
                        fs.Write(remainderBuf);
                    }
                    Console.WriteLine($"Processed: {path + "_dec.bundle"}");
                }
            } 
            catch(FileLoadException)
            {
                Console.WriteLine($"{path} does not seem to be NKAB!");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
    }
}
