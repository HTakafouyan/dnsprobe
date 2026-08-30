using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using DnsProbe.Network;

namespace DnsProbe.Dns;

/// <summary>
/// Sends DNS queries over a socket that is explicitly bound to the caller's chosen
/// source address and pinned to the caller's chosen interface index.
/// </summary>
/// <remarks>
/// The UDP socket is deliberately <em>not</em> connected, so that responses coming from an
/// unexpected address are visible to the tool instead of being silently dropped by the stack.
/// Every received datagram is validated (source endpoint, minimum length, transaction ID,
/// question section) before it is accepted.
/// </remarks>
public sealed class DnsClient
{
    private const int UdpReceiveBufferSize = 4096;
    private const int MaxTcpMessageSize = 65535;

    private readonly ISocketFactory _socketFactory;

    public DnsClient(ISocketFactory socketFactory)
    {
        _socketFactory = socketFactory;
    }

    /// <summary>
    /// Runs one logical query: initial attempt, optional retries, and optional TCP fallback
    /// when the UDP answer has TC=1.
    /// </summary>
    /// <param name="request">The query definition.</param>
    /// <param name="retries">Number of <em>additional</em> attempts after the first one.</param>
    /// <param name="tcpFallback">Retry over TCP when the UDP response is truncated.</param>
    /// <param name="cancellationToken">Cancels the whole operation.</param>
    public async Task<DnsQueryResult> QueryAsync(
        DnsQueryRequest request,
        int retries,
        bool tcpFallback,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var attempts = new List<DnsQueryAttempt>();
        bool usedTcpFallback = false;
        bool usedEdnsFallback = false;
        DnsQueryRequest current = request;

        for (int attempt = 0; attempt <= retries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            DnsQueryAttempt result = await SendOnceAsync(current, current.Transport, cancellationToken)
                .ConfigureAwait(false);
            attempts.Add(result);

            // Some middleboxes and old resolvers drop or reject queries carrying an OPT record.
            // Retrying without EDNS turns a mysterious timeout into a concrete finding.
            if (!usedEdnsFallback && ShouldRetryWithoutEdns(current, result))
            {
                usedEdnsFallback = true;
                current = current.WithoutEdns();

                DnsQueryAttempt plain = await SendOnceAsync(current, current.Transport, cancellationToken)
                    .ConfigureAwait(false);

                attempts.Add(WithNote(
                    plain,
                    plain.IsSuccess
                        ? "The query with an EDNS(0) OPT record failed, but the same query without EDNS "
                          + "succeeded. Something on this path does not tolerate EDNS - use --no-edns here."
                        : "The query was retried without EDNS(0) and failed as well, so EDNS is probably "
                          + "not the cause."));

                result = attempts[^1];
            }

            if (result.IsSuccess)
            {
                if (tcpFallback
                    && current.Transport == DnsTransport.Udp
                    && result.Response is not null
                    && result.Response.Header.Truncated)
                {
                    usedTcpFallback = true;
                    DnsQueryAttempt overTcp = await SendOnceAsync(current, DnsTransport.Tcp, cancellationToken)
                        .ConfigureAwait(false);
                    attempts.Add(overTcp);
                }

                break;
            }

            // Retrying a refused/unreachable destination is pointless; only transient failures are retried.
            if (result.Outcome is DnsQueryOutcome.ConfigurationError
                or DnsQueryOutcome.AccessDenied
                or DnsQueryOutcome.ConnectionRefused
                or DnsQueryOutcome.PinnedInterfaceUnreachable
                or DnsQueryOutcome.NetworkUnreachable)
            {
                break;
            }
        }

        return new DnsQueryResult(attempts, usedTcpFallback, usedEdnsFallback);
    }

    /// <summary>
    /// Decides whether it is worth repeating the query without an OPT record. Only failures that
    /// EDNS could plausibly have caused qualify: silence, or a server that rejected the message.
    /// </summary>
    private static bool ShouldRetryWithoutEdns(DnsQueryRequest request, DnsQueryAttempt attempt)
    {
        if (request.Edns is null || !request.Edns.Enabled)
        {
            return false;
        }

        if (attempt.Outcome == DnsQueryOutcome.Timeout)
        {
            return true;
        }

        if (attempt.Outcome != DnsQueryOutcome.Success || attempt.Response is null)
        {
            return false;
        }

        return attempt.Response.Header.ResponseCode is DnsResponseCode.FormErr or DnsResponseCode.NotImp;
    }

    private static DnsQueryAttempt WithNote(DnsQueryAttempt attempt, string note)
    {
        var notes = new List<string>(attempt.Notes.Count + 1);
        notes.AddRange(attempt.Notes);
        notes.Add(note);

        return new DnsQueryAttempt
        {
            Outcome = attempt.Outcome,
            Transport = attempt.Transport,
            TransactionId = attempt.TransactionId,
            Response = attempt.Response,
            QueryBytes = attempt.QueryBytes,
            ResponseBytes = attempt.ResponseBytes,
            LocalEndPoint = attempt.LocalEndPoint,
            RemoteEndPoint = attempt.RemoteEndPoint,
            RoundTripTime = attempt.RoundTripTime,
            ErrorMessage = attempt.ErrorMessage,
            SocketError = attempt.SocketError,
            Notes = notes,
        };
    }

    /// <summary>
    /// Reads the local endpoint without ever throwing. The runtime disposes the socket when an
    /// async connect is cancelled, so this is not always safe to read after a failure.
    /// </summary>
    private static IPEndPoint? SafeLocalEndPoint(Socket? socket)
    {
        try
        {
            return socket?.LocalEndPoint as IPEndPoint;
        }
        catch (ObjectDisposedException)
        {
            return null;
        }
        catch (SocketException)
        {
            return null;
        }
    }

    /// <summary>Performs exactly one send/receive cycle.</summary>
    public async Task<DnsQueryAttempt> SendOnceAsync(
        DnsQueryRequest request,
        DnsTransport transport,
        CancellationToken cancellationToken)
    {
        ushort transactionId = DnsPacketBuilder.CreateTransactionId();
        byte[] query;

        try
        {
            query = DnsPacketBuilder.BuildQuery(
                transactionId,
                request.Name,
                request.RecordType,
                request.RecursionDesired,
                request.RecordClass,
                request.Edns);
        }
        catch (DnsProtocolException ex)
        {
            return new DnsQueryAttempt
            {
                Outcome = DnsQueryOutcome.ConfigurationError,
                Transport = transport,
                TransactionId = transactionId,
                ErrorMessage = ex.Message,
            };
        }

        if (request.Server.AddressFamily != request.Binding.Family)
        {
            return new DnsQueryAttempt
            {
                Outcome = DnsQueryOutcome.ConfigurationError,
                Transport = transport,
                TransactionId = transactionId,
                ErrorMessage =
                    $"The DNS server {request.Server.Address} and the selected local address family do not match.",
            };
        }

        var notes = new List<string>();
        Socket? socket = null;

        try
        {
            var binding = new SocketBinding(
                request.Binding.Family,
                transport == DnsTransport.Tcp ? ProtocolType.Tcp : ProtocolType.Udp,
                request.Binding.SourceAddress,
                request.Binding.InterfaceIndex,
                request.Binding.UseUnicastInterfaceOption);

            socket = _socketFactory.Create(binding, out IReadOnlyList<string> socketNotes);
            notes.AddRange(socketNotes);

            using var timeoutSource = new CancellationTokenSource(request.TimeoutMilliseconds);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);

            var stopwatch = Stopwatch.StartNew();

            byte[] responseBytes = transport == DnsTransport.Tcp
                ? await SendOverTcpAsync(socket, request, query, transactionId, notes, linked.Token).ConfigureAwait(false)
                : await SendOverUdpAsync(socket, request, query, transactionId, notes, linked.Token).ConfigureAwait(false);

            stopwatch.Stop();

            IPEndPoint? localEndPoint = SafeLocalEndPoint(socket);

            if (!DnsPacketParser.TryParse(responseBytes, out DnsMessage? message, out string? parseError))
            {
                return new DnsQueryAttempt
                {
                    Outcome = DnsQueryOutcome.MalformedResponse,
                    Transport = transport,
                    TransactionId = transactionId,
                    QueryBytes = query,
                    ResponseBytes = responseBytes,
                    LocalEndPoint = localEndPoint,
                    RemoteEndPoint = request.Server,
                    RoundTripTime = stopwatch.Elapsed,
                    ErrorMessage = parseError,
                    Notes = notes,
                };
            }

            ValidateQuestionEcho(message!, request, notes);

            return new DnsQueryAttempt
            {
                Outcome = DnsQueryOutcome.Success,
                Transport = transport,
                TransactionId = transactionId,
                Response = message,
                QueryBytes = query,
                ResponseBytes = responseBytes,
                LocalEndPoint = localEndPoint,
                RemoteEndPoint = request.Server,
                RoundTripTime = stopwatch.Elapsed,
                Notes = notes,
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new DnsQueryAttempt
            {
                Outcome = DnsQueryOutcome.Timeout,
                Transport = transport,
                TransactionId = transactionId,
                QueryBytes = query,
                LocalEndPoint = SafeLocalEndPoint(socket),
                RemoteEndPoint = request.Server,
                RoundTripTime = TimeSpan.FromMilliseconds(request.TimeoutMilliseconds),
                ErrorMessage = transport == DnsTransport.Tcp
                    ? $"No TCP response from {request.Server} within {request.TimeoutMilliseconds} ms "
                      + "(the connection or the answer did not complete)."
                    : $"DNS request timed out after {request.TimeoutMilliseconds} ms.",
                Notes = notes,
            };
        }
        catch (ObjectDisposedException)
        {
            // Cancelling Socket.ConnectAsync disposes the socket from inside the runtime, so a
            // TCP connect that hits the timeout surfaces here rather than as a cancellation.
            return new DnsQueryAttempt
            {
                Outcome = DnsQueryOutcome.Timeout,
                Transport = transport,
                TransactionId = transactionId,
                QueryBytes = query,
                RemoteEndPoint = request.Server,
                RoundTripTime = TimeSpan.FromMilliseconds(request.TimeoutMilliseconds),
                ErrorMessage = transport == DnsTransport.Tcp
                    ? $"The TCP connection to {request.Server} did not complete within {request.TimeoutMilliseconds} ms."
                    : $"DNS request timed out after {request.TimeoutMilliseconds} ms.",
                Notes = notes,
            };
        }
        catch (SocketConfigurationException ex)
        {
            return new DnsQueryAttempt
            {
                Outcome = DnsQueryOutcome.ConfigurationError,
                Transport = transport,
                TransactionId = transactionId,
                QueryBytes = query,
                ErrorMessage = ex.Message,
                Notes = notes,
            };
        }
        catch (SocketException ex)
        {
            return new DnsQueryAttempt
            {
                Outcome = MapSocketError(ex.SocketErrorCode, request),
                Transport = transport,
                TransactionId = transactionId,
                QueryBytes = query,
                LocalEndPoint = SafeLocalEndPoint(socket),
                RemoteEndPoint = request.Server,
                ErrorMessage = DescribeSocketError(ex, request),
                SocketError = ex.SocketErrorCode,
                Notes = notes,
            };
        }
        catch (DnsProtocolException ex)
        {
            return new DnsQueryAttempt
            {
                Outcome = DnsQueryOutcome.MalformedResponse,
                Transport = transport,
                TransactionId = transactionId,
                QueryBytes = query,
                LocalEndPoint = SafeLocalEndPoint(socket),
                RemoteEndPoint = request.Server,
                ErrorMessage = ex.Message,
                Notes = notes,
            };
        }
        finally
        {
            socket?.Dispose();
        }
    }

    private static async Task<byte[]> SendOverUdpAsync(
        Socket socket,
        DnsQueryRequest request,
        byte[] query,
        ushort transactionId,
        List<string> notes,
        CancellationToken cancellationToken)
    {
        await socket.SendToAsync(query, SocketFlags.None, request.Server, cancellationToken).ConfigureAwait(false);

        // Never receive less than we advertised, or a legitimate large answer would be cut off.
        int bufferSize = Math.Max(UdpReceiveBufferSize, request.Edns?.ReceiveBufferSize ?? 0);
        byte[] buffer = new byte[bufferSize];
        EndPoint anyEndPoint = request.Binding.Family == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            SocketReceiveFromResult received = await socket
                .ReceiveFromAsync(buffer, SocketFlags.None, anyEndPoint, cancellationToken)
                .ConfigureAwait(false);

            if (received.RemoteEndPoint is not IPEndPoint sender || !sender.Equals(request.Server))
            {
                notes.Add($"Ignored a datagram from an unexpected sender ({received.RemoteEndPoint}).");
                continue;
            }

            if (received.ReceivedBytes < DnsPacketBuilder.HeaderLength)
            {
                notes.Add($"Ignored a {received.ReceivedBytes} byte datagram that is too short to be a DNS message.");
                continue;
            }

            ushort responseId = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(0, 2));
            if (responseId != transactionId)
            {
                notes.Add($"Ignored a response with transaction ID 0x{responseId:X4}; 0x{transactionId:X4} was expected.");
                continue;
            }

            byte[] response = new byte[received.ReceivedBytes];
            Buffer.BlockCopy(buffer, 0, response, 0, received.ReceivedBytes);
            return response;
        }
    }

    private static async Task<byte[]> SendOverTcpAsync(
        Socket socket,
        DnsQueryRequest request,
        byte[] query,
        ushort transactionId,
        List<string> notes,
        CancellationToken cancellationToken)
    {
        await socket.ConnectAsync(request.Server, cancellationToken).ConfigureAwait(false);

        byte[] framed = DnsPacketBuilder.FrameForTcp(query);
        int sent = 0;
        while (sent < framed.Length)
        {
            sent += await socket
                .SendAsync(framed.AsMemory(sent), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
        }

        byte[] lengthPrefix = await ReadExactlyAsync(socket, 2, cancellationToken).ConfigureAwait(false);
        int messageLength = BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix);

        if (messageLength < DnsPacketBuilder.HeaderLength)
        {
            throw new DnsProtocolException(
                $"The DNS server announced a {messageLength} byte TCP message, which is too short to be valid.");
        }

        if (messageLength > MaxTcpMessageSize)
        {
            throw new DnsProtocolException($"The DNS server announced an impossible message length of {messageLength} bytes.");
        }

        byte[] response = await ReadExactlyAsync(socket, messageLength, cancellationToken).ConfigureAwait(false);

        ushort responseId = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(0, 2));
        if (responseId != transactionId)
        {
            throw new DnsProtocolException(
                $"The TCP response carried transaction ID 0x{responseId:X4} instead of the expected 0x{transactionId:X4}.");
        }

        notes.Add($"DNS over TCP: {framed.Length} bytes sent (2 byte length prefix included), {response.Length} bytes received.");
        return response;
    }

    private static async Task<byte[]> ReadExactlyAsync(Socket socket, int count, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[count];
        int read = 0;

        while (read < count)
        {
            int chunk = await socket
                .ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);

            if (chunk == 0)
            {
                throw new DnsProtocolException(
                    $"The DNS server closed the TCP connection after {read} of {count} expected bytes.");
            }

            read += chunk;
        }

        return buffer;
    }

    /// <summary>
    /// A conforming server echoes the question section. A mismatch is not fatal, but it is
    /// worth surfacing because it can indicate an interception/proxy device on the path.
    /// </summary>
    private static void ValidateQuestionEcho(DnsMessage message, DnsQueryRequest request, List<string> notes)
    {
        if (message.Questions.Count == 0)
        {
            if (message.Header.ResponseCode == DnsResponseCode.NoError)
            {
                notes.Add("The response contains no question section.");
            }

            return;
        }

        DnsQuestion question = message.Questions[0];
        string expected = request.Name.TrimEnd('.');
        string actual = question.Name.TrimEnd('.');

        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
        {
            notes.Add($"The response echoed the question \"{question.Name}\" instead of \"{request.Name}\".");
        }

        if (question.Type != request.RecordType)
        {
            notes.Add($"The response echoed query type {question.Type.ToDisplayString()} instead of {request.RecordType.ToDisplayString()}.");
        }
    }

    /// <summary>True when the socket was actually pinned to an interface with IP_UNICAST_IF.</summary>
    private static bool IsPinned(DnsQueryRequest request) =>
        request.Binding.InterfaceIndex is not null && request.Binding.UseUnicastInterfaceOption;

    private static DnsQueryOutcome MapSocketError(SocketError error, DnsQueryRequest request) => error switch
    {
        System.Net.Sockets.SocketError.NetworkUnreachable => DnsQueryOutcome.NetworkUnreachable,
        System.Net.Sockets.SocketError.NetworkDown => DnsQueryOutcome.NetworkUnreachable,
        System.Net.Sockets.SocketError.HostUnreachable => DnsQueryOutcome.HostUnreachable,
        System.Net.Sockets.SocketError.ConnectionRefused => DnsQueryOutcome.ConnectionRefused,
        System.Net.Sockets.SocketError.ConnectionReset => DnsQueryOutcome.ConnectionRefused,
        System.Net.Sockets.SocketError.AccessDenied => DnsQueryOutcome.AccessDenied,
        System.Net.Sockets.SocketError.TimedOut => DnsQueryOutcome.Timeout,

        // WSAEINVAL on a pinned socket means the pinned interface has no route to the
        // destination; on an unpinned socket it really is a bad argument.
        System.Net.Sockets.SocketError.InvalidArgument when IsPinned(request)
            => DnsQueryOutcome.PinnedInterfaceUnreachable,

        _ => DnsQueryOutcome.SocketFailure,
    };

    private static string DescribeSocketError(SocketException ex, DnsQueryRequest request) => ex.SocketErrorCode switch
    {
        System.Net.Sockets.SocketError.NetworkUnreachable =>
            $"Network is unreachable: Windows has no route from the selected source address to {request.Server.Address}.",
        System.Net.Sockets.SocketError.NetworkDown =>
            "The network is down on the selected interface.",
        System.Net.Sockets.SocketError.HostUnreachable =>
            $"No route to the DNS server {request.Server.Address} (ICMP host unreachable).",
        System.Net.Sockets.SocketError.ConnectionRefused =>
            $"Connection refused by {request.Server}: nothing is listening on that port.",
        System.Net.Sockets.SocketError.ConnectionReset =>
            $"{request.Server} replied with ICMP port unreachable: no DNS service is listening on UDP/{request.Server.Port}.",
        System.Net.Sockets.SocketError.AccessDenied =>
            "Access denied while creating or binding the socket. A firewall or policy may be blocking it.",
        System.Net.Sockets.SocketError.AddressNotAvailable =>
            "The requested source address is not available on this machine any more.",
        System.Net.Sockets.SocketError.InvalidArgument when IsPinned(request) =>
            $"The pinned interface (index {request.Binding.InterfaceIndex}) has no route to "
            + $"{request.Server.Address}. IP_UNICAST_IF restricts the route lookup to that interface, "
            + "so Windows rejected the send instead of using a different one. Re-run with "
            + "--no-unicast-if to see which interface the routing table would have chosen.",

        System.Net.Sockets.SocketError.InvalidArgument =>
            "The socket rejected the requested binding or interface option (invalid argument).",
        _ => $"Socket error {ex.SocketErrorCode} ({ex.ErrorCode}): {ex.Message}",
    };
}
