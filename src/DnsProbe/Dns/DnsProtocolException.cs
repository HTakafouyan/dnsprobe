namespace DnsProbe.Dns;

/// <summary>
/// Raised when a DNS message cannot be encoded or safely decoded.
/// Every parsing failure funnels through this type so that the caller never has to
/// deal with IndexOutOfRange / Overflow style exceptions coming from network data.
/// </summary>
public sealed class DnsProtocolException : Exception
{
    public DnsProtocolException(string message)
        : base(message)
    {
    }

    public DnsProtocolException(string message, Exception inner)
        : base(message, inner)
    {
    }
}
