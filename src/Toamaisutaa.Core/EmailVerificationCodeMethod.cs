using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// The default <see cref="IEmailVerificationMethod"/>: six digits, mailed through
/// <see cref="IEmailVerificationNotifier.SendCodeAsync"/>, kept as a keyed hash.
/// </summary>
internal sealed class EmailVerificationCodeMethod(
    IServiceProvider provider,
    EmailVerificationCodeHashes hashes,
    IOptions<ToamaisutaaLocalLoginOptions> options,
    TimeProvider timeProvider,
    ILogger<EmailVerificationCodeMethod> logger) : IEmailVerificationMethod
{
    internal const string MethodName = "code";

    /// <summary>Wrong tries one code takes before it is spent. Lockout caps the account sooner or later anyway.</summary>
    internal const int MaxAttempts = 5;

    public string Name => MethodName;

    public async Task<EmailVerificationIssueResult> IssueAsync(EmailVerificationIssueRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var codes = provider.GetRequiredService<IEmailVerificationCodeStore>();
        var notifier = provider.GetService<IEmailVerificationNotifier>()
            ?? throw new InvalidOperationException(
                $"No {nameof(IEmailVerificationNotifier)} is registered. The default email-verification method mails its code through one.");

        var now = timeProvider.GetUtcNow();
        var cooldown = options.Value.MailRequestCooldown;

        // Read from the store rather than an in-memory cooldown, so every instance agrees and a sign-in
        // inside it leaves the code already in the mailbox working.
        if (cooldown > TimeSpan.Zero
            && await codes.FindLatestAsync(request.User.Id, cancellationToken) is { } latest
            && latest.CreatedAt + cooldown > now)
        {
            return EmailVerificationIssueResult.CoolingDown(latest.CreatedAt + cooldown - now);
        }

        await codes.InvalidateAllForUserAsync(request.User.Id, now, cancellationToken);

        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
        var lifetime = options.Value.EmailVerificationCodeLifetime;

        await codes.CreateAsync(
            new ToamaisutaaEmailVerificationCode
            {
                Id = Guid.CreateVersion7(now),
                UserId = request.User.Id,
                NormalizedEmail = Normalizer.Normalize(request.Email),
                CodeHash = hashes.Hash(request.User.Id, code),
                CreatedAt = now,
                ExpiresAt = now + lifetime,
            },
            cancellationToken);

        await notifier.SendCodeAsync(request.User, request.Email, code, lifetime, cancellationToken);

        logger.LogInformation("Email verification code issued for user {UserId} and handed to the notifier.", request.User.Id);

        return EmailVerificationIssueResult.Sent;
    }

    public async Task<EmailVerificationProofOutcome> VerifyAsync(EmailVerificationProofRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var codes = provider.GetRequiredService<IEmailVerificationCodeStore>();
        var now = timeProvider.GetUtcNow();
        var latest = await codes.FindLatestAsync(request.User.Id, cancellationToken);

        if (latest is null
            || latest.ConsumedAt is not null
            || latest.ExpiresAt <= now
            || !string.Equals(latest.NormalizedEmail, Normalizer.Normalize(request.Email), StringComparison.Ordinal))
        {
            return EmailVerificationProofOutcome.Expired;
        }

        // Counted before it is compared, so parallel guesses cannot each find tries left.
        if (!await codes.TryReserveAttemptAsync(latest.Id, MaxAttempts, cancellationToken))
            return EmailVerificationProofOutcome.Expired;

        if (Normalize(request.Proof) is { } typed && hashes.Matches(latest.CodeHash, request.User.Id, typed))
        {
            return await codes.MarkConsumedAsync(latest.Id, now, cancellationToken)
                ? EmailVerificationProofOutcome.Verified
                : EmailVerificationProofOutcome.Expired;
        }

        if (latest.FailedAttempts + 1 < MaxAttempts)
            return EmailVerificationProofOutcome.Invalid;

        await codes.MarkConsumedAsync(latest.Id, now, cancellationToken);
        logger.LogWarning("Email verification code for user {UserId} spent after {MaxAttempts} wrong tries.", request.User.Id, MaxAttempts);

        return EmailVerificationProofOutcome.Exhausted;
    }

    /// <summary>Spaces and hyphens are what people put in a code they copied; anything else is not one.</summary>
    private static string? Normalize(string proof)
    {
        var digits = new string([.. proof.Where(character => character is not (' ' or '-'))]);
        return digits.Length == 6 && digits.All(char.IsAsciiDigit) ? digits : null;
    }
}

/// <summary>
/// Keyed, because six digits under a plain hash fall to anyone holding a copy of the table at once. The
/// key is derived from the local signing key, which every deployment of password login already has, so
/// turning the option on needs no new secret; rotating the signing key retires codes in flight.
/// </summary>
internal sealed class EmailVerificationCodeHashes(IOptions<ToamaisutaaLocalLoginOptions> options, LocalSigningKeyRing signingKeys)
{
    private static readonly byte[] Purpose = "toamaisutaa:email-verification-codes"u8.ToArray();

    private readonly Lazy<byte[]> _key = new(() => Derive(options.Value, signingKeys));

    internal string Hash(Guid userId, string code) => Convert.ToBase64String(Mac(userId, code));

    internal bool Matches(string storedHash, Guid userId, string code)
    {
        Span<byte> stored = stackalloc byte[HMACSHA256.HashSizeInBytes];

        return Convert.TryFromBase64String(storedHash, stored, out var written)
            && written == HMACSHA256.HashSizeInBytes
            && CryptographicOperations.FixedTimeEquals(stored, Mac(userId, code));
    }

    /// <summary>Bound to the user, so a row copied onto another account does not verify there.</summary>
    private byte[] Mac(Guid userId, string code) =>
        HMACSHA256.HashData(_key.Value, (byte[])[.. userId.ToByteArray(), .. Encoding.UTF8.GetBytes(code)]);

    private static byte[] Derive(ToamaisutaaLocalLoginOptions settings, LocalSigningKeyRing signingKeys)
    {
        var material = signingKeys.Active is { } active
            ? active.Key.ExportPkcs8PrivateKey()
            : !string.IsNullOrWhiteSpace(settings.SigningKey)
                ? Convert.FromBase64String(settings.SigningKey)
                : throw new InvalidOperationException(
                    "Neither LocalLogin:SigningKey nor LocalLogin:SigningKeys is set, so there is no key to store email verification codes under.");

        return HKDF.DeriveKey(HashAlgorithmName.SHA256, material, 32, info: Purpose);
    }
}
