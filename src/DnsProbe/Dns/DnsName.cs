using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DnsProbe.Dns;

/// <summary>
/// Encoding and (defensive) decoding of DNS names.
/// </summary>
/// <remarks>
/// All decoding here treats the input as hostile network data:
/// <list type="bullet">
/// <item>every read is bounds checked against the message buffer,</item>
/// <item>compression pointers must point strictly backwards, which makes pointer loops impossible,</item>
/// <item>the number of pointer jumps is capped anyway (belt and braces),</item>
/// <item>the total decoded name length is capped at 255 bytes as required by RFC 1035,</item>
/// <item>label length is capped at 63 bytes,</item>
/// <item>the two reserved label-type bits (0b01 / 0b10) are rejected instead of being ignored.</item>
/// </list>
/// Decoding is iterative, so there is no recursion and therefore no stack overflow risk.
/// </remarks>
public static class DnsName
{
    public const int MaxNameLength = 255;
    public const int MaxLabelLength = 63;
    private const int MaxPointerJumps = 64;

    /// <summary>
    /// Encodes a textual domain name into DNS wire format (length-prefixed labels + root label).
    /// Unicode names are converted to punycode (IDNA).
    /// </summary>
    public static byte[] Encode(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        string normalized = Normalize(name);
        if (normalized.Length == 0)
        {
            return new byte[] { 0 };
        }

        string[] labels = normalized.Split('.');
        var buffer = new List<byte>(normalized.Length + 2);

        foreach (string label in labels)
        {
            if (label.Length == 0)
            {
                throw new DnsProtocolException($"Invalid domain name '{name}': it contains an empty label.");
            }

            byte[] bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length > MaxLabelLength)
            {
                throw new DnsProtocolException(
                    $"Invalid domain name '{name}': label '{label}' is {bytes.Length} bytes (maximum is {MaxLabelLength}).");
            }

            buffer.Add((byte)bytes.Length);
            buffer.AddRange(bytes);
        }

        buffer.Add(0);

        if (buffer.Count > MaxNameLength)
        {
            throw new DnsProtocolException(
                $"Invalid domain name '{name}': encoded length is {buffer.Count} bytes (maximum is {MaxNameLength}).");
        }

        return buffer.ToArray();
    }

    /// <summary>Validates a query name without throwing. Returns false and an explanation on failure.</summary>
    public static bool TryValidate(string name, out string? error)
    {
        try
        {
            Encode(name);
            error = null;
            return true;
        }
        catch (DnsProtocolException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Trims a trailing root dot and converts any non-ASCII characters to punycode.
    /// </summary>
    private static string Normalize(string name)
    {
        string trimmed = name.Trim();
        if (trimmed == "." || trimmed.Length == 0)
        {
            return string.Empty;
        }

        if (trimmed.EndsWith('.'))
        {
            trimmed = trimmed[..^1];
        }

        bool needsIdn = false;
        foreach (char c in trimmed)
        {
            if (c > 127)
            {
                needsIdn = true;
                break;
            }
        }

        if (!needsIdn)
        {
            return trimmed;
        }

        try
        {
            return new IdnMapping { AllowUnassigned = true, UseStd3AsciiRules = false }.GetAscii(trimmed);
        }
        catch (ArgumentException ex)
        {
            throw new DnsProtocolException($"Invalid internationalized domain name '{name}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Reads a (possibly compressed) DNS name starting at <paramref name="offset"/>.
    /// On return <paramref name="offset"/> points to the first byte after the name
    /// as it appears at the original position - i.e. after the first pointer, if any.
    /// </summary>
    public static string Read(ReadOnlySpan<byte> message, ref int offset)
    {
        if (offset < 0 || offset >= message.Length)
        {
            throw new DnsProtocolException($"Malformed DNS message: name offset {offset} is outside the message.");
        }

        var builder = new StringBuilder(64);
        int position = offset;
        int jumps = 0;
        bool jumped = false;
        int decodedLength = 0;

        while (true)
        {
            if (position < 0 || position >= message.Length)
            {
                throw new DnsProtocolException("Malformed DNS message: name extends past the end of the message.");
            }

            byte lengthByte = message[position];
            int labelType = lengthByte & 0xC0;

            if (labelType == 0x00)
            {
                position++;

                if (lengthByte == 0)
                {
                    if (!jumped)
                    {
                        offset = position;
                    }

                    break;
                }

                int labelLength = lengthByte;
                if (position + labelLength > message.Length)
                {
                    throw new DnsProtocolException("Malformed DNS message: label extends past the end of the message.");
                }

                decodedLength += labelLength + 1;
                if (decodedLength > MaxNameLength)
                {
                    throw new DnsProtocolException(
                        $"Malformed DNS message: decoded name exceeds {MaxNameLength} bytes.");
                }

                AppendLabel(builder, message.Slice(position, labelLength));
                builder.Append('.');
                position += labelLength;
            }
            else if (labelType == 0xC0)
            {
                if (position + 1 >= message.Length)
                {
                    throw new DnsProtocolException("Malformed DNS message: truncated compression pointer.");
                }

                int pointer = ((lengthByte & 0x3F) << 8) | message[position + 1];

                if (!jumped)
                {
                    offset = position + 2;
                    jumped = true;
                }

                // A compression pointer must reference a strictly earlier position.
                // This single rule makes infinite pointer loops impossible.
                if (pointer >= position)
                {
                    throw new DnsProtocolException(
                        $"Malformed DNS message: compression pointer at {position} points forward to {pointer}.");
                }

                if (++jumps > MaxPointerJumps)
                {
                    throw new DnsProtocolException("Malformed DNS message: too many compression pointer jumps.");
                }

                position = pointer;
            }
            else
            {
                throw new DnsProtocolException(
                    $"Malformed DNS message: reserved label type 0x{labelType:X2} at offset {position}.");
            }
        }

        return builder.Length == 0 ? "." : builder.ToString();
    }

    /// <summary>
    /// Appends a label to the output, escaping bytes that are not printable ASCII
    /// so that hostile data can never corrupt the console output.
    /// </summary>
    private static void AppendLabel(StringBuilder builder, ReadOnlySpan<byte> label)
    {
        foreach (byte b in label)
        {
            if (b == (byte)'.' || b == (byte)'\\')
            {
                builder.Append('\\').Append((char)b);
            }
            else if (b < 0x21 || b > 0x7E)
            {
                builder.Append('\\').Append(b.ToString("000", CultureInfo.InvariantCulture));
            }
            else
            {
                builder.Append((char)b);
            }
        }
    }

    /// <summary>
    /// Builds the reverse lookup (PTR) name for an IP address:
    /// 8.8.8.8 -> 8.8.8.8.in-addr.arpa
    /// 2001:db8::1 -> 1.0.0....2.ip6.arpa
    /// </summary>
    public static string ToReverseLookupName(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        byte[] bytes = address.GetAddressBytes();

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return string.Create(CultureInfo.InvariantCulture,
                $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa");
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var builder = new StringBuilder(72);
            for (int i = bytes.Length - 1; i >= 0; i--)
            {
                builder.Append(HexDigit(bytes[i] & 0x0F)).Append('.');
                builder.Append(HexDigit((bytes[i] >> 4) & 0x0F)).Append('.');
            }

            builder.Append("ip6.arpa");
            return builder.ToString();
        }

        throw new DnsProtocolException($"Reverse lookup is not supported for address family {address.AddressFamily}.");
    }

    private static char HexDigit(int value) => (char)(value < 10 ? '0' + value : 'a' + (value - 10));
}
