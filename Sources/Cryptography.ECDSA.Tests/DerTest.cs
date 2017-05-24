using System.Linq;
using NUnit.Framework;

namespace Cryptography.ECDSA.Tests
{
    [TestFixture]
    public class DerTest : BaseTest
    {
        [Test]
        [TestCase(0, "00")]
        [TestCase(1, "01")]
        [TestCase(16, "10")]
        [TestCase(127, "7f")]
        [TestCase(128, "8180")]
        [TestCase(255, "81ff")]
        [TestCase(256, "820100")]
        [TestCase(257, "820101")]
        [TestCase(2048, "820800")]
        [TestCase(65536, "83010000")]
        public void VarInt(int key, string value)
        {
            var val = Der.EncodeLength(key);
            var rez = string.Join(string.Empty, val.Select(i => i.ToString("x2")));
            Assert.IsTrue(value.Equals(rez), $"{value} != {rez}");
        }

        [Test]
        public void ReadLengthTest()
        {
            var l = Hex.HexToBytes("3045022100fc4e72b69b89def7126732ebca8ecaf4277cf657ded7df7a821045474002201e0220597c084c3aa821eea65b957f4f0f5f70d7e49b27d93809e7617b1f7518e82c41");
            var  tpl = Der.ReadLength(l);
            Assert.IsTrue(tpl.Item1 == 48);
            Assert.IsTrue(tpl.Item2 == 1);
        }
    }
}