using Xunit;
using Xunit.Abstractions;

namespace Cryptography.ECDSA.Tests
{
    public class HexTest : BaseTest
    {
        public HexTest(ITestOutputHelper output) : base(output)
        {
        }

        [Theory]
        [InlineData(0, "00")]
        [InlineData(0, "0000")]
        [InlineData(1, "1")]
        [InlineData(1, "01")]
        [InlineData(16, "10")]
        [InlineData(127, "7f")]
        [InlineData(128, "80")]
        [InlineData(255, "ff")]
        [InlineData(256, "100")]
        [InlineData(257, "101")]
        [InlineData(2048, "800")]
        [InlineData(65536, "10000")]
        [InlineData(int.MaxValue, "7fffffff")]
        [InlineData(int.MinValue, "80000000")]
        public void ConvertIntTest(int key, string hex)
        {
            var hexStr = Hex.HexToBytes(hex);
            var value = Hex.HexToInteger(hexStr);
            Assert.True(key == value);
        }
    }
}