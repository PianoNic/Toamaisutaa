using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core.Tests;

/// <summary>Everything wired with in-memory stores, so the flows can be exercised without a host.</summary>
internal sealed class PasswordHarness
{
    internal static readonly DateTimeOffset Start = new(2026, 8, 11, 12, 0, 0, TimeSpan.Zero);

    private PasswordHarness(
        ToamaisutaaLocalLoginOptions options,
        ToamaisutaaTwoFactorOptions twoFactorOptions,
        ToamaisutaaTrustedDeviceOptions trustedDeviceOptions,
        bool withTwoFactor,
        bool withTrustedDevices,
        bool withAdminPasswordNotifier)
    {
        TrustedDeviceOptions = trustedDeviceOptions;

        Clock = new FixedTimeProvider(Start);
        Options = options;
        TwoFactorOptions = twoFactorOptions;

        var wrapped = Microsoft.Extensions.Options.Options.Create(options);
        var wrappedTwoFactor = Microsoft.Extensions.Options.Options.Create(twoFactorOptions);

        Users = new FakeStore(Clock);
        Passwords = new FakePasswordStore();
        Issuer = new FakeAccessTokenIssuer(Clock);
        Notifier = new FakePasswordResetNotifier();
        AdminPasswordNotifier = new FakeAdminPasswordIssuedNotifier();
        Hasher = new Pbkdf2PasswordHasher(wrapped);

        TwoFactorStore = new FakeTwoFactorStore();
        Totp = new TotpProvider(wrappedTwoFactor);
        RecoveryCodes = new RecoveryCodeProvider();
        Protector = new AesGcmSecretProtector(wrappedTwoFactor);

        Verifier = new TwoFactorVerifier(
            TwoFactorStore,
            TwoFactorStore,
            Totp,
            RecoveryCodes,
            Protector,
            wrappedTwoFactor,
            Clock,
            NullLogger<TwoFactorVerifier>.Instance);

        var provider = new FakeServiceProvider();

        // Registered by default, so most tests get it for free; the one test about the missing-
        // notifier failure asks for it to be left out instead.
        if (withAdminPasswordNotifier)
            provider.Add<IAdminPasswordIssuedNotifier>(AdminPasswordNotifier);

        // Registered only when the test asks for it, so the "password login with no second factor
        // configured" path is exercised by every other test rather than assumed.
        if (withTwoFactor)
        {
            provider
                .Add<ITwoFactorStore>(TwoFactorStore)
                .Add<IRecoveryCodeStore>(TwoFactorStore)
                .Add<ITwoFactorChallengeStore>(TwoFactorStore)
                .Add(Verifier);
        }

        var gate = new TwoFactorGate(provider, wrappedTwoFactor, NullLogger<TwoFactorGate>.Instance);

        Devices = new FakeTrustedDeviceStore();

        if (withTrustedDevices)
            provider.Add<ITrustedDeviceStore>(Devices);

        var deviceGate = new TrustedDeviceGate(
            provider,
            Microsoft.Extensions.Options.Options.Create(trustedDeviceOptions),
            NullLogger<TrustedDeviceGate>.Instance);

        TrustedDevices = new TrustedDeviceService(Devices, Clock, NullLogger<TrustedDeviceService>.Instance);

        SignIn = new PasswordSignInService(
            Passwords,
            Users,
            Passwords,
            Hasher,
            Issuer,
            new EmptyUserRoleProvider(),
            new DummyPasswordHash(Hasher),
            gate,
            deviceGate,
            wrapped,
            Clock,
            NullLogger<PasswordSignInService>.Instance);

        Accounts = new PasswordAccountService(
            Passwords,
            Users,
            Passwords,
            Passwords,
            Hasher,
            new DefaultPasswordValidator(wrapped),
            Notifier,
            SignIn,
            deviceGate,
            wrapped,
            Clock,
            NullLogger<PasswordAccountService>.Instance,
            provider);

        TwoFactor = new TwoFactorService(
            TwoFactorStore,
            TwoFactorStore,
            Users,
            Passwords,
            Totp,
            RecoveryCodes,
            Protector,
            Verifier,
            deviceGate,
            wrappedTwoFactor,
            Clock,
            NullLogger<TwoFactorService>.Instance);
    }

    internal FixedTimeProvider Clock { get; }

    internal ToamaisutaaLocalLoginOptions Options { get; }

    internal ToamaisutaaTwoFactorOptions TwoFactorOptions { get; }

    internal FakeStore Users { get; }

    internal FakePasswordStore Passwords { get; }

    internal FakeAccessTokenIssuer Issuer { get; }

    internal FakePasswordResetNotifier Notifier { get; }

    internal FakeAdminPasswordIssuedNotifier AdminPasswordNotifier { get; }

    internal Pbkdf2PasswordHasher Hasher { get; }

    internal FakeTwoFactorStore TwoFactorStore { get; }

    internal TotpProvider Totp { get; }

    internal RecoveryCodeProvider RecoveryCodes { get; }

    internal AesGcmSecretProtector Protector { get; }

    internal TwoFactorVerifier Verifier { get; }

    internal PasswordSignInService SignIn { get; }

    internal PasswordAccountService Accounts { get; }

    internal TwoFactorService TwoFactor { get; }

    internal FakeTrustedDeviceStore Devices { get; }

    internal TrustedDeviceService TrustedDevices { get; }

    internal ToamaisutaaTrustedDeviceOptions TrustedDeviceOptions { get; }

    /// <summary>What every existing test used to call directly, kept as a helper so the request
    /// record does not have to appear in fifty places.</summary>
    internal Task<SignInResult> SignInAsync(string identifier, string password, string? deviceToken = null) =>
        SignIn.SignInAsync(new PasswordSignInRequest
        {
            Identifier = identifier,
            Password = password,
            DeviceToken = deviceToken,
        });

    internal Task<SignInResult> VerifyAsync(string challenge, string code, bool rememberDevice = false, string? label = null) =>
        SignIn.VerifyTwoFactorAsync(new TwoFactorSignInRequest
        {
            ChallengeToken = challenge,
            Code = code,
            RememberDevice = rememberDevice,
            DeviceLabel = label,
        });

    internal static PasswordHarness Create(
        Action<ToamaisutaaLocalLoginOptions>? configure = null,
        Action<ToamaisutaaTwoFactorOptions>? configureTwoFactor = null,
        Action<ToamaisutaaTrustedDeviceOptions>? configureTrustedDevices = null,
        bool withTwoFactor = false,
        bool withTrustedDevices = false,
        bool withAdminPasswordNotifier = true)
    {
        // Iterations far below the production floor: these tests run many derivations and the floor
        // is a startup check, not a property of the hasher.
        var options = new ToamaisutaaLocalLoginOptions { Pbkdf2Iterations = 1_000 };
        configure?.Invoke(options);

        var twoFactor = new ToamaisutaaTwoFactorOptions
        {
            EncryptionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        };

        configureTwoFactor?.Invoke(twoFactor);

        var trustedDevices = new ToamaisutaaTrustedDeviceOptions();
        configureTrustedDevices?.Invoke(trustedDevices);

        return new PasswordHarness(options, twoFactor, trustedDevices, withTwoFactor, withTrustedDevices, withAdminPasswordNotifier);
    }

    /// <summary>A registered local account, as self-registration would have produced it.</summary>
    internal async Task<ToamaisutaaUser> RegisterAsync(string userName = "pianonic", string? email = "nic@example.com", string password = "correct horse battery")
    {
        var result = await Accounts.RegisterAsync(new RegisterRequest(userName, email, password));

        if (!result.Succeeded)
            throw new InvalidOperationException($"Registration failed: {string.Join("; ", result.Errors)}");

        return Users.Users.Single(user => user.Id == result.UserId);
    }

    /// <summary>An account as OIDC provisioning would have left it: a user row, an external login,
    /// and no password at all.</summary>
    internal ToamaisutaaUser ProvisionExternalUser(string email = "sso@example.com", string userName = "ssouser")
    {
        var user = new ToamaisutaaUser
        {
            Id = Guid.CreateVersion7(Clock.GetUtcNow()),
            UserName = userName,
            Email = email,
            DisplayName = "SSO Person",
            SecurityStamp = Guid.NewGuid().ToString("N"),
            CreatedAt = Clock.GetUtcNow(),
            UpdatedAt = Clock.GetUtcNow(),
        };

        Users.Users.Add(user);
        return user;
    }

    /// <summary>Enrols a user end to end - begin, read the secret back, confirm with a real code -
    /// and hands back the plaintext secret and the recovery codes.</summary>
    internal async Task<(byte[] Secret, IReadOnlyList<string> RecoveryCodes)> EnrolAsync(Guid userId)
    {
        var started = await TwoFactor.BeginEnrolmentAsync(userId);

        if (!Base32.TryDecode(started.Secret, out var secret))
            throw new InvalidOperationException("The enrolment secret is not valid base32.");

        var completed = await TwoFactor.ConfirmEnrolmentAsync(userId, CurrentCode(secret));

        return (secret, completed.RecoveryCodes);
    }

    /// <summary>The code an authenticator app would be showing at the harness clock's current
    /// moment.</summary>
    internal string CurrentCode(byte[] secret, int stepOffset = 0)
    {
        var period = TwoFactorOptions.Period;
        return TotpCodes.Compute(secret, Clock.GetUtcNow() + (stepOffset * period), period, TwoFactorOptions.Digits);
    }
}
