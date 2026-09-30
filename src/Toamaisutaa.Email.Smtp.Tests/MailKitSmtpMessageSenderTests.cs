using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Toamaisutaa.Email.Smtp.Tests;

/// <summary>Runs against a real socket, because what is under test is what goes over the wire.</summary>
public class MailKitSmtpMessageSenderTests
{
    /// <summary>A server without STARTTLS is what a stripping attacker presents; MailKit's own Auto
    /// sends the login in the clear there.</summary>
    [Test]
    public async Task The_default_security_never_sends_the_login_to_a_server_without_starttls()
    {
        await using var server = PlaintextSmtpServer.Start();

        var sender = new MailKitSmtpMessageSender(Options.Create(new ToamaisutaaSmtpEmailOptions
        {
            Host = "127.0.0.1",
            Port = server.Port,
            From = "noreply@example.com",
            User = "relay-user",
            Password = "relay-password",
            Timeout = TimeSpan.FromSeconds(10),
        }));

        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse("noreply@example.com"));
        message.To.Add(MailboxAddress.Parse("ada@example.com"));
        message.Subject = "Reset";
        message.Body = new TextPart("plain") { Text = "https://app.example.com/reset?token=secret" };

        await Assert.That(async () => await sender.SendAsync(message, CancellationToken.None)).ThrowsException();

        await Assert.That(server.Received.Any(line => line.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase))).IsFalse();
        await Assert.That(server.Received.Any(line => line.Contains("token=secret", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    [Arguments(465, MailKit.Security.SecureSocketOptions.SslOnConnect)]
    [Arguments(587, MailKit.Security.SecureSocketOptions.StartTls)]
    [Arguments(25, MailKit.Security.SecureSocketOptions.StartTls)]
    public async Task Auto_always_requires_tls(int port, MailKit.Security.SecureSocketOptions expected)
    {
        await Assert.That(MailKitSmtpMessageSender.ToSecureSocketOptions(SmtpSecurityMode.Auto, port)).IsEqualTo(expected);
    }

    private sealed class PlaintextSmtpServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;

        private PlaintextSmtpServer()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            _loop = Task.Run(ServeAsync);
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public ConcurrentQueue<string> Received { get; } = new();

        public static PlaintextSmtpServer Start() => new();

        private async Task ServeAsync()
        {
            try
            {
                using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                await using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII);
                await using var writer = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };

                await writer.WriteLineAsync("220 relay.example.com ESMTP");
                var inData = false;

                while (await reader.ReadLineAsync(_stop.Token) is { } line)
                {
                    Received.Enqueue(line);

                    if (inData)
                    {
                        if (line == ".")
                        {
                            inData = false;
                            await writer.WriteLineAsync("250 queued");
                        }

                        continue;
                    }

                    var verb = line.Split(' ')[0].ToUpperInvariant();

                    switch (verb)
                    {
                        case "EHLO":
                            await writer.WriteLineAsync("250-relay.example.com");
                            await writer.WriteLineAsync("250 AUTH PLAIN LOGIN");
                            break;
                        case "AUTH":
                            await writer.WriteLineAsync("235 authenticated");
                            break;
                        case "DATA":
                            inData = true;
                            await writer.WriteLineAsync("354 go ahead");
                            break;
                        case "QUIT":
                            await writer.WriteLineAsync("221 bye");
                            return;
                        default:
                            await writer.WriteLineAsync("250 ok");
                            break;
                    }
                }
            }
            catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException or ObjectDisposedException)
            {
                // The client hung up, or the test is over.
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _listener.Stop();
            await _loop;
            _stop.Dispose();
        }
    }
}
