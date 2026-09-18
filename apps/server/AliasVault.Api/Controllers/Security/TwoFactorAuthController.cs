//-----------------------------------------------------------------------
// <copyright file="TwoFactorAuthController.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Api.Controllers.Security;

using System.Data;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AliasServerDb;
using AliasVault.Api.Controllers.Abstracts;
using AliasVault.Auth;
using AliasVault.Shared.Models.Enums;
using Asp.Versioning;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OtpNet;

/// <summary>Manages session-bound 2FA setup and confirmed removal.</summary>
/// <param name="db">The scoped identity database context.</param>
/// <param name="cache">Short-lived, session-bound setup secrets.</param>
/// <param name="urlEncoder">URL encoder.</param>
/// <param name="authLoggingService">Authentication audit logger.</param>
/// <param name="userManager">Identity user manager.</param>
[Route("v{version:apiVersion}/[controller]")]
[ApiController]
[ApiVersion("1")]
public class TwoFactorAuthController(AliasServerDbContext db, IMemoryCache cache, UrlEncoder urlEncoder, AuthLoggingService authLoggingService, UserManager<AliasVaultUser> userManager) : AuthenticatedRequestController(userManager)
{
    /// <summary>Returns whether 2FA is enabled.</summary>
    /// <returns>The current status.</returns>
    [HttpGet("status")]
    public async Task<IActionResult> Status()
    {
        var user = await GetCurrentUserAsync();
        return user is null ? Unauthorized() : Ok(new { TwoFactorEnabled = user.TwoFactorEnabled });
    }

    /// <summary>Starts setup without exposing or replacing an active authenticator.</summary>
    /// <returns>A temporary setup secret for this session only.</returns>
    [HttpPost("enable")]
    public async Task<IActionResult> Enable()
    {
        var user = await GetCurrentUserAsync();
        if (user is null || !Guid.TryParse(User.FindFirstValue("sid"), out _))
        {
            return Unauthorized();
        }

        if (user.TwoFactorEnabled || await GetUserManager().IsLockedOutAsync(user))
        {
            return Conflict("Two-factor authentication is already enabled or the account is locked.");
        }

        var secret = cache.GetOrCreate(SetupCacheKey(user.Id), entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10);
            return Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        })!;
        var qrCodeUrl = $"otpauth://totp/{urlEncoder.Encode("AliasVault")}:{urlEncoder.Encode(user.UserName!)}?secret={urlEncoder.Encode(secret)}&issuer=AliasVault";
        return Ok(new { Secret = secret, QrCodeUrl = qrCodeUrl });
    }

    /// <summary>Confirms the temporary authenticator and issues recovery codes once.</summary>
    /// <param name="code">The six-digit authenticator code.</param>
    /// <returns>Recovery codes on successful setup.</returns>
    [HttpPost("verify")]
    public Task<IActionResult> Verify([FromBody] string code)
    {
        return db.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            db.ChangeTracker.Clear();
            return await VerifyCore(code);
        });
    }

    /// <summary>Disables 2FA only after checking the current second factor.</summary>
    /// <param name="code">The current six-digit authenticator code.</param>
    /// <returns>Success when the authenticator was removed.</returns>
    [HttpPost("disable")]
    public Task<IActionResult> Disable([FromBody] string code)
    {
        return db.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            db.ChangeTracker.Clear();
            return await DisableCore(code);
        });
    }

    private static bool IsCodeFormatValid(string? code) => code is { Length: 6 } && code.All(c => c is >= '0' and <= '9');

    private async Task<IActionResult> VerifyCore(string code)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var user = await GetCurrentUserAsync();
        if (user is null)
        {
            return Unauthorized();
        }

        if (user.TwoFactorEnabled || await GetUserManager().IsLockedOutAsync(user))
        {
            return Conflict("Two-factor authentication is already enabled or the account is locked.");
        }

        if (!cache.TryGetValue<string>(SetupCacheKey(user.Id), out var secret) || secret is null)
        {
            return BadRequest("Setup expired. Start setup again.");
        }

        if (!IsCodeFormatValid(code) || !AliasVault.TotpGenerator.TotpGenerator.VerifyTotpCode(secret, code))
        {
            await GetUserManager().AccessFailedAsync(user);
            await transaction.CommitAsync();
            return BadRequest("Invalid code.");
        }

        var result = await GetUserManager().SetAuthenticationTokenAsync(user, "[AspNetUserStore]", "AuthenticatorKey", secret);
        if (!result.Succeeded || !(await GetUserManager().SetTwoFactorEnabledAsync(user, true)).Succeeded)
        {
            return Conflict("Setup changed. Start setup again.");
        }

        var recoveryCodes = (await GetUserManager().GenerateNewTwoFactorRecoveryCodesAsync(user, 10))?.ToArray();
        await GetUserManager().ResetAccessFailedCountAsync(user);
        await transaction.CommitAsync();
        cache.Remove(SetupCacheKey(user.Id));
        await authLoggingService.LogAuthEventSuccessAsync(user.UserName!, AuthEventType.TwoFactorAuthEnable);
        return Ok(new { RecoveryCodes = recoveryCodes });
    }

    private async Task<IActionResult> DisableCore(string code)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var user = await GetCurrentUserAsync();
        if (user is null)
        {
            return Unauthorized();
        }

        if (!user.TwoFactorEnabled || await GetUserManager().IsLockedOutAsync(user))
        {
            return BadRequest("Two-factor authentication is not enabled or the account is locked.");
        }

        if (!IsCodeFormatValid(code) || !await GetUserManager().VerifyTwoFactorTokenAsync(user, GetUserManager().Options.Tokens.AuthenticatorTokenProvider, code))
        {
            await GetUserManager().AccessFailedAsync(user);
            await transaction.CommitAsync();
            await authLoggingService.LogAuthEventFailAsync(user.UserName!, AuthEventType.TwoFactorAuthDisable, AuthFailureReason.InvalidTwoFactorCode);
            return BadRequest("Invalid code.");
        }

        if (!(await GetUserManager().SetTwoFactorEnabledAsync(user, false)).Succeeded)
        {
            return Conflict("Authentication settings changed. Try again.");
        }

        db.UserTokens.RemoveRange(await db.UserTokens.Where(t => t.UserId == user.Id
            && t.LoginProvider == "[AspNetUserStore]" && (t.Name == "AuthenticatorKey" || t.Name == "RecoveryCodes")).ToListAsync());
        await db.SaveChangesAsync();
        await GetUserManager().ResetAccessFailedCountAsync(user);
        await transaction.CommitAsync();
        cache.Remove(SetupCacheKey(user.Id));
        await authLoggingService.LogAuthEventSuccessAsync(user.UserName!, AuthEventType.TwoFactorAuthDisable);
        return Ok();
    }

    private string SetupCacheKey(string userId) => $"2fa-setup:{userId}:{User.FindFirstValue("sid")}";
}
