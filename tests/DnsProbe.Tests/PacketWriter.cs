using System.Text;
using DnsProbe.Dns;

namespace DnsProbe.Tests;

/// <summary>Minimal DNS wire format writer used to build synthetic responses in tests.</summary>
internal sealed class PacketWriter
{
    private readonly List<byte> _bytes = new();

    public int Position => _bytes.Count;

    public PacketWriter WriteByte(byte value)
    {
        _bytes.Add(value);
        return this;
    }

    public PacketWriter WriteBytes(params byte[] values)
    {
        _bytes.AddRange(values);
        return this;
    }

    public PacketWriter WriteUInt16(ushort value)
    {
        _bytes.Add((byte)(value >> 8));
        _bytes.Add((byte)(value & 0xFF));
        return this;
    }

    public PacketWriter WriteUInt32(uint value)
    {
        _bytes.Add((byte)(value >> 24));
        _bytes.Add((byte)((value >> 16) & 0xFF));
        _bytes.Add((byte)((value >> 8) & 0xFF));
        _bytes.Add((byte)(value & 0xFF));
        return this;
    }

    /// <summary>Writes an uncompressed name terminated by the root label.</summary>
    public PacketWriter WriteName(string name)
    {
        if (name is "." or "")
        {
            return WriteByte(0);
        }

        foreach (string label in name.TrimEnd('.').Split('.'))
        {
            byte[] bytes = Encoding.ASCII.GetBytes(label);
            WriteByte((byte)bytes.Length);
            WriteBytes(bytes);
        }

        return WriteByte(0);
    }

    /// <summary>Writes a compression pointer to an absolute offset.</summary>
    public PacketWriter WritePointer(int offset)
    {
        WriteByte((byte)(0xC0 | ((offset >> 8) & 0x3F)));
        WriteByte((byte)(offset & 0xFF));
        return this;
    }

    /// <summary>Writes the 12 byte header.</summary>
    public PacketWriter WriteHeader(
        ushort id,
        ushort flags,
        ushort questions,
        ushort answers,
        ushort authorities = 0,
        ushort additionals = 0)
    {
        WriteUInt16(id);
        WriteUInt16(flags);
        WriteUInt16(questions);
        WriteUInt16(answers);
        WriteUInt16(authorities);
        WriteUInt16(additionals);
        return this;
    }

    public PacketWriter WriteQuestion(string name, DnsRecordType type, DnsRecordClass cls = DnsRecordClass.IN)
    {
        WriteName(name);
        WriteUInt16((ushort)type);
        WriteUInt16((ushort)cls);
        return this;
    }

    /// <summary>Writes a record header and its RDATA, computing RDLENGTH automatically.</summary>
    public PacketWriter WriteRecord(
        Action<PacketWriter> nameWriter,
        DnsRecordType type,
        uint ttl,
        Action<PacketWriter> rdataWriter,
        DnsRecordClass cls = DnsRecordClass.IN)
    {
        nameWriter(this);
        WriteUInt16((ushort)type);
        WriteUInt16((ushort)cls);
        WriteUInt32(ttl);

        int lengthPosition = Position;
        WriteUInt16(0);

        int rdataStart = Position;
        rdataWriter(this);
        int rdataLength = Position - rdataStart;

        _bytes[lengthPosition] = (byte)(rdataLength >> 8);
        _bytes[lengthPosition + 1] = (byte)(rdataLength & 0xFF);
        return this;
    }

    public byte[] ToArray() => _bytes.ToArray();
}

internal static class Flags
{
    public const ushort Response = 0x8000;
    public const ushort AuthoritativeAnswer = 0x0400;
    public const ushort Truncated = 0x0200;
    public const ushort RecursionDesired = 0x0100;
    public const ushort RecursionAvailable = 0x0080;

    public static ushort WithRcode(ushort flags, DnsResponseCode code) => (ushort)(flags | (ushort)code);

    public const ushort StandardResponse = Response | RecursionDesired | RecursionAvailable;
}
