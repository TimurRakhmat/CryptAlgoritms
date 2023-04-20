// See https://aka.ms/new-console-template for more information
using Des;
using Rijndael;
using System.ComponentModel;

Console.WriteLine("Hello, World!");


byte a = 0x57;
byte b = 0x83;
byte c = 0x1b;

byte r = GaloisField.mul(a, b, c);

byte bb = GaloisField.inverse(b);

r = GaloisField.mul(b, bb);

Console.WriteLine(r);