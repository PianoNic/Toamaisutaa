using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toamaisutaa.Abstractions;
using Toamaisutaa.Core;
using Toamaisutaa.EntityFrameworkCore;

namespace Toamaisutaa.AspNetCore.Tests;

/// <summary>
/// The store keeps instants to the millisecond and the lockout state is computed at full precision,
/// so a reservation read back never equalled itself. A right code whose reservation set the lock then
/// could not undo it, and the account stayed locked.
/// </summary>
public class EnrolmentLockoutPrecisionTests
{
    [Test]
    public async Task A_right_code_undoes_the_lock_its_own_reservation_set_off_a_whole_millisecond()
    {
        await using var app = await TestApp.StartAsync();
        var account = await Account.RegisterAsync(app);
        await account.EnrolAsync();

        var userId = Guid.Parse(account.Claims().String("sub")!);
        var options = new ToamaisutaaLocalLoginOptions();

        // Half a millisecond in, which the store cannot keep.
        var now = app.Time.Now.AddTicks(5_000);
        await Assert.That(now.Ticks % TimeSpan.TicksPerMillisecond).IsNotEqualTo(0);

        await using var scope = app.Services.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<ITwoFactorStore>();

        EnrolmentReservation last = default;
        for (var i = 0; i < options.MaxFailedAttempts; i++)
            last = await store.ReserveAttemptAsync(userId, options, now, CancellationToken.None);

        await Assert.That(last.LockedUntil.HasValue).IsTrue();

        await store.TryRefundAttemptAsync(userId, last, now, CancellationToken.None);

        await using var check = app.Services.CreateAsyncScope();
        var stored = await check.ServiceProvider.GetRequiredService<ToamaisutaaDbContext>()
            .UserTwoFactors.AsNoTracking().SingleAsync();

        await Assert.That(stored.LockedOutUntil.HasValue).IsFalse();
        await Assert.That(stored.FailedAttemptCount).IsEqualTo(options.MaxFailedAttempts - 1);
    }
}
