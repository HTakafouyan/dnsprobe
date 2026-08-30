using System.Text;

namespace DnsProbe.Diagnostics;

/// <summary>Classic 16-bytes-per-line hex dump used by --debug.</summary>
public static class HexDump
{
    public static string Format(ReadOnlySpan<byte> data, string indent = "  ")
    {
        if (data.Length == 0)
        {
            return indent + "(empty)";
        }

        var builder = new StringBuilder(data.Length * 4);

        for (int offset = 0; offset < data.Length; offset += 16)
        {
            int lineLength = Math.Min(16, data.Length - offset);

            builder.Append(indent).Append(offset.ToString("X4", System.Globalization.CultureInfo.InvariantCulture)).Append("  ");

            for (int i = 0; i < 16; i++)
            {
                if (i < lineLength)
                {
                    builder.Append(data[offset + i].ToString("X2", System.Globalization.CultureInfo.InvariantCulture)).Append(' ');
                }
                else
                {
                    builder.Append("   ");
                }

                if (i == 7)
                {
                    builder.Append(' ');
                }
            }

            builder.Append(" |");

            for (int i = 0; i < lineLength; i++)
            {
                byte b = data[offset + i];
                builder.Append(b is >= 0x20 and <= 0x7E ? (char)b : '.');
            }

            builder.Append('|');

            if (offset + 16 < data.Length)
            {
                builder.Append('\n');
            }
        }

        return builder.ToString();
    }
}
