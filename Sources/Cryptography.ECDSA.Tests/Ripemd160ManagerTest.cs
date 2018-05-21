using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Cryptography.ECDSA.Tests
{
    public class Ripemd160ManagerTest : BaseTest
    {
        public Ripemd160ManagerTest(ITestOutputHelper output) : base(output)
        {
        }

        [Theory]
        [InlineData("", "9c1185a5c5e9fc54612808977ee8f548b2258d31")]
        [InlineData("The quick brown fox jumps over the lazy cog", "132072df690933835eb8b6ad0b77e7b6f14acad7")]
        [InlineData("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")]
        public void CompareHashTest(string key, string expected)
        {
            var buf = Encoding.ASCII.GetBytes(key);
            var t = Ripemd160Manager.GetHash(buf);

            Assert.Equal(expected, Hex.ToString(t));
        }
    }
}
