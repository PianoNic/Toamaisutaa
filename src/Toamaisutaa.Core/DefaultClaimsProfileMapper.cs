using System.Security.Claims;
using Microsoft.Extensions.Options;
using Toamaisutaa.Abstractions;

namespace Toamaisutaa.Core;

/// <summary>
/// Reads the standard OIDC claims off a validated principal. Public so a custom mapper can delegate
/// to it for the parts it does not want to reimplement.
/// </summary>
/// <remarks>
/// Claim types are the raw JWT names, because the bearer layer disables inbound claim mapping.
/// <c>sub</c> falls back to <see cref="ClaimTypes.NameIdentifier"/> so a principal that went
/// through .NET's inbound map still resolves.
/// </remarks>
public sealed class DefaultClaimsProfileMapper(IOptions<ToamaisutaaProvisioningOptions> options) : IClaimsProfileMapper
{
    public ExternalUserProfile Map(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var names = options.Value.ClaimNames;

        var subject = Find(principal, names.Subject) ?? Find(principal, ClaimTypes.NameIdentifier);
        if (subject is null)
        {
            throw new InvalidOperationException(
                $"The principal carries no '{names.Subject}' claim, so it cannot be linked to a local user. "
                + "Check that the token includes a subject and that ToamaisutaaClaimNames.Subject matches your issuer.");
        }

        var userName = Find(principal, names.UserName);
        var email = Find(principal, names.Email);
        var displayName = Find(principal, names.DisplayName);

        return new ExternalUserProfile
        {
            Subject = subject,
            Issuer = Find(principal, names.Issuer),
            UserName = userName,
            Email = email,
            // A human's name first: preferred_username is a handle, and this field is displayed.
            DisplayName = displayName ?? userName ?? email,
            PictureUrl = Find(principal, names.Picture),
        };
    }

    /// <summary>First non-blank value for a claim type, or null. Blank is the same as absent: an
    /// issuer that sends an empty string should not overwrite a stored value with nothing.</summary>
    private static string? Find(ClaimsPrincipal principal, string claimType)
    {
        foreach (var claim in principal.FindAll(claimType))
        {
            if (!string.IsNullOrWhiteSpace(claim.Value))
                return claim.Value;
        }

        return null;
    }
}
