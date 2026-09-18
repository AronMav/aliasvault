//-----------------------------------------------------------------------
// <copyright file="SecurityRegressionTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Services;

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using AliasServerDb;
using AliasVault.Api;
using AliasVault.Api.Controllers;
using AliasVault.Api.Helpers;
using AliasVault.Api.Jwt;
using AliasVault.Api.Services;
using AliasVault.Auth;
using AliasVault.Auth.IpAddress;
using AliasVault.Cryptography.Server;
using AliasVault.Shared.Models.Configuration;
using AliasVault.Shared.Providers.Time;
using AliasVault.Shared.Server.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

/// <summary>Defensive HTTP regression tests against a dedicated local PostgreSQL database.</summary>
[NonParallelizable]
[Category("SecurityDatabaseTests")]
public class SecurityRegressionTests
{
    private IHost _host = null!;
    private TestServer _server = null!;
    private HttpClient _client = null!;
    private string _jwtKey = null!;
    private string? _previousJwtKey;
    private string? _previousConnection;
    private string _userId = null!;
    private Guid _sessionId;
    private Guid _refreshId;
    private string _refreshToken = null!;
    private string _publicKey = null!;
    private RSA _rsa = null!;

    /// <summary>Starts only the dedicated test application and seeds a synthetic account.</summary>
    /// <returns>The setup task.</returns>
    [SetUp]
    public async Task SetUp()
    {
        var connection = Environment.GetEnvironmentVariable("ALIASVAULT_SECURITY_TEST_DB");
        if (string.IsNullOrEmpty(connection))
        {
            Assert.Ignore("Set ALIASVAULT_SECURITY_TEST_DB to a dedicated local PostgreSQL database.");
        }

        var parsed = new Npgsql.NpgsqlConnectionStringBuilder(connection);
        Assert.That(parsed.Host, Is.AnyOf("localhost", "127.0.0.1"));
        Assert.That(parsed.Database, Does.StartWith("aliasvault_security_test"));
        _previousJwtKey = Environment.GetEnvironmentVariable("JWT_KEY");
        _previousConnection = Environment.GetEnvironmentVariable("ConnectionStrings__AliasServerDbContext");
        _jwtKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        Environment.SetEnvironmentVariable("JWT_KEY", _jwtKey);
        Environment.SetEnvironmentVariable("ConnectionStrings__AliasServerDbContext", connection);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:AliasServerDbContext"] = connection,
            ["Jwt:Issuer"] = "security-tests",
        }).Build();
        _host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddSingleton<IConfiguration>(configuration);
            services.AddLogging();
            services.AddSingleton<IAliasServerDbContextFactory, PostgresqlDbContextFactory>();
            services.AddDbContextFactory<AliasServerDbContext>((sp, options) => sp.GetRequiredService<IAliasServerDbContextFactory>().ConfigureDbContextOptions(options));
            services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<AliasServerDbContext>>().CreateDbContext());
            services.AddDataProtection().UseEphemeralDataProtectionProvider();
            services.AddIdentity<AliasVaultUser, AliasVaultRole>(options => options.Lockout.MaxFailedAccessAttempts = 3)
                .AddEntityFrameworkStores<AliasServerDbContext>().AddDefaultTokenProviders();
            services.AddSingleton<ITimeProvider, SystemTimeProvider>();
            services.AddSingleton(new Config());
            services.AddSingleton<SharedConfig>(sp => sp.GetRequiredService<Config>());
            services.AddMemoryCache();
            services.AddHttpContextAccessor();
            services.AddSingleton(UrlEncoder.Default);
            services.AddScoped<AuthLoggingService>();
            services.AddScoped<ServerSettingsService>();
            services.AddScoped<RegistrationRateLimitService>();
            services.AddScoped<MobileLoginRateLimitService>();
            services.AddScoped<IpBlockListService>();
            services.AddScoped<RateLimitService>();
            services.AddSingleton<AnonymousAuthRateLimitService>();
            services.AddScoped<TimeValidationJwtBearerEvents>();
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = "security-tests", ValidAudience = "security-tests",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey)),
                    ValidateLifetime = true, ClockSkew = TimeSpan.Zero,
                };
                options.EventsType = typeof(TimeValidationJwtBearerEvents);
            });
            services.AddAuthorization();
            services.AddApiVersioning().AddMvc();
            services.AddControllers().AddApplicationPart(typeof(AuthController).Assembly);
        }).Configure(app =>
        {
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapControllers());
        })).StartAsync();
        _server = _host.GetTestServer();

        using var scope = _server.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AliasServerDbContext>();
        await db.Database.MigrateAsync();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<AliasVaultUser>>();
        var user = new AliasVaultUser { UserName = "security" + Guid.NewGuid().ToString("N"), LockoutEnabled = true };
        Assert.That((await manager.CreateAsync(user)).Succeeded, Is.True);
        _userId = user.Id;
        _sessionId = Guid.NewGuid();
        _refreshId = Guid.NewGuid();
        _refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        db.UserSessions.Add(new UserSession { Id = _sessionId, UserId = _userId, CreatedAt = DateTime.UtcNow });
        db.AliasVaultUserRefreshTokens.Add(new AliasVaultUserRefreshToken
        {
            Id = _refreshId, SessionId = _sessionId, UserId = _userId, DeviceIdentifier = "test-device",
            Value = AuthHelper.HashRefreshToken(_refreshToken), CreatedAt = DateTime.UtcNow, ExpireDate = DateTime.UtcNow.AddHours(1),
        });
        _rsa = RSA.Create(2048);
        var key = _rsa.ExportParameters(false);
        _publicKey = JsonSerializer.Serialize(new { kty = "RSA", n = Base64UrlEncoder.Encode(key.Modulus!), e = Base64UrlEncoder.Encode(key.Exponent!) });
        db.UserEncryptionKeys.Add(new UserEncryptionKey { UserId = _userId, PublicKey = _publicKey, IsPrimary = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();
        var token = new JwtSecurityToken(
            "security-tests",
            "security-tests",
            [new Claim(ClaimTypes.NameIdentifier, _userId), new Claim("sid", _sessionId.ToString())],
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey)), SecurityAlgorithms.HmacSha256));
        _client = _server.CreateClient();
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", new JwtSecurityTokenHandler().WriteToken(token));
    }

    /// <summary>Releases the test host and restores process configuration.</summary>
    [TearDown]
    public void TearDown()
    {
        _client?.Dispose();
        _server?.Dispose();
        _host?.Dispose();
        _rsa?.Dispose();
        Environment.SetEnvironmentVariable("JWT_KEY", _previousJwtKey);
        Environment.SetEnvironmentVariable("ConnectionStrings__AliasServerDbContext", _previousConnection);
    }

    /// <summary>Setup is temporary, active secrets stay private, and removal needs a valid code.</summary>
    /// <returns>The regression test task.</returns>
    [Test]
    public async Task TwoFactorLifecycleRequiresConfirmation()
    {
        var setup = await (await _client.PostAsync("/v1/TwoFactorAuth/enable", null)).Content.ReadFromJsonAsync<JsonElement>();
        var secret = setup.GetProperty("secret").GetString()!;
        var code = AliasVault.TotpGenerator.TotpGenerator.GenerateTotpCode(secret);
        Assert.That((await _client.PostAsJsonAsync("/v1/TwoFactorAuth/verify", code)).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await _client.PostAsync("/v1/TwoFactorAuth/enable", null)).StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
        Assert.That((await _client.PostAsJsonAsync("/v1/TwoFactorAuth/verify", code)).StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
        Assert.That((await _client.PostAsJsonAsync("/v1/TwoFactorAuth/disable", string.Empty)).StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That((await _client.PostAsJsonAsync("/v1/TwoFactorAuth/disable", "invalid")).StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That((await _client.PostAsJsonAsync("/v1/TwoFactorAuth/disable", code)).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    /// <summary>Revoking a refresh session immediately invalidates its access token.</summary>
    /// <returns>The regression test task.</returns>
    [Test]
    public async Task RevocationInvalidatesAccessToken()
    {
        Assert.That((await _client.GetAsync("/v1/TwoFactorAuth/status")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await _client.DeleteAsync($"/v1/Security/sessions/{_refreshId}")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await _client.GetAsync("/v1/TwoFactorAuth/status")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    /// <summary>A blocked account cannot continue using authenticated endpoints.</summary>
    /// <returns>The regression test task.</returns>
    [Test]
    public async Task BlockingInvalidatesAccessToken()
    {
        using var scope = _server.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AliasServerDbContext>();
        await db.AliasVaultUsers.Where(u => u.Id == _userId).ExecuteUpdateAsync(u => u.SetProperty(x => x.Blocked, true));
        Assert.That((await _client.GetAsync("/v1/TwoFactorAuth/status")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    /// <summary>A rotated token keeps the same revocable session.</summary>
    /// <returns>The regression test task.</returns>
    [Test]
    public async Task RefreshPreservesRevocableSession()
    {
        var response = await _client.PostAsJsonAsync("/v1/Auth/refresh", new { token = _client.DefaultRequestHeaders.Authorization!.Parameter, refreshToken = _refreshToken });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var tokens = await response.Content.ReadFromJsonAsync<JsonElement>();
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("token").GetString());
        Assert.That((await _client.GetAsync("/v1/TwoFactorAuth/status")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await _client.DeleteAsync($"/v1/Security/sessions/{_sessionId}")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await _client.GetAsync("/v1/TwoFactorAuth/status")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    /// <summary>Ordinary sync cannot replace the mail trust anchor or write a vault before rejection.</summary>
    /// <returns>The regression test task.</returns>
    [Test]
    public async Task SyncCannotReplaceMailKey()
    {
        using var scope = _server.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AliasServerDbContext>();
        var user = await db.AliasVaultUsers.SingleAsync(u => u.Id == _userId);
        using var otherKey = RSA.Create(2048);
        var parameters = otherKey.ExportParameters(false);
        var publicKey = JsonSerializer.Serialize(new { kty = "RSA", n = Base64UrlEncoder.Encode(parameters.Modulus!), e = Base64UrlEncoder.Encode(parameters.Exponent!) });
        var response = await _client.PostAsJsonAsync("/v1/Vault", new AliasVault.Shared.Models.WebApi.Vault.Vault
        {
            Username = user.UserName!, Blob = "synthetic", Version = "1.0.0", CurrentRevisionNumber = 0,
            CredentialsCount = 0, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow, EncryptionPublicKey = publicKey,
        });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
        Assert.That(await db.Vaults.AnyAsync(v => v.UserId == _userId), Is.False);
        Assert.That(await db.UserEncryptionKeys.Where(k => k.UserId == _userId && k.IsPrimary).Select(k => k.PublicKey).SingleAsync(), Is.EqualTo(_publicKey));
    }

    /// <summary>The migration backfills existing refresh tokens without changing their hashes.</summary>
    /// <returns>The regression test task.</returns>
    [Test]
    public async Task MigrationPreservesExistingRefreshTokens()
    {
        using var scope = _server.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AliasServerDbContext>();
        var migrations = db.Database.GetMigrations().ToArray();
        var migrator = db.GetService<IMigrator>();
        await migrator.MigrateAsync(migrations[^2]);
        await migrator.MigrateAsync(migrations[^1]);
        db.ChangeTracker.Clear();
        var refresh = await db.AliasVaultUserRefreshTokens.SingleAsync(t => t.Id == _refreshId);
        Assert.That(refresh.SessionId, Is.EqualTo(_refreshId));
        Assert.That(refresh.Value, Is.EqualTo(AuthHelper.HashRefreshToken(_refreshToken)));
        Assert.That(await db.UserSessions.AnyAsync(t => t.Id == _refreshId && t.RevokedAt == null), Is.True);
    }

    /// <summary>The resolved native SQLite engine includes the security fixes.</summary>
    [Test]
    public void NativeSqliteIsPatched()
    {
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT sqlite_version()";
        Assert.That(Version.Parse((string)command.ExecuteScalar()!), Is.GreaterThanOrEqualTo(new Version(3, 50, 2)));
    }

    /// <summary>Mobile approval needs the vault-key proof, an active approving session, and is collected once.</summary>
    /// <param name="revokeBeforePoll">Whether to revoke the approving session before retrieval.</param>
    /// <returns>The regression test task.</returns>
    [TestCase(false)]
    [TestCase(true)]
    public async Task MobileApprovalRequiresVaultKeyAndIsSingleUse(bool revokeBeforePoll)
    {
        var initiated = await _client.PostAsJsonAsync("/v1/Auth/mobile-login/initiate", new { clientPublicKey = _publicKey });
        var id = (await initiated.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("requestId").GetString()!;
        const string encryptedKey = "synthetic-test-ciphertext";
        Assert.That((await _client.PostAsJsonAsync("/v1/Auth/mobile-login/submit", new { requestId = id, encryptedDecryptionKey = encryptedKey })).StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        var signature = Convert.ToBase64String(_rsa.SignData(Encoding.UTF8.GetBytes(MobileLoginApproval.CreatePayload(id, _publicKey, encryptedKey)), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Assert.That((await _client.PostAsJsonAsync("/v1/Auth/mobile-login/submit", new { requestId = id, encryptedDecryptionKey = encryptedKey, approvalSignature = signature })).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        if (revokeBeforePoll)
        {
            Assert.That((await _client.DeleteAsync($"/v1/Security/sessions/{_sessionId}")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That((await _client.GetAsync($"/v1/Auth/mobile-login/poll/{id}")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            return;
        }

        var polls = await Task.WhenAll(_client.GetAsync($"/v1/Auth/mobile-login/poll/{id}"), _client.GetAsync($"/v1/Auth/mobile-login/poll/{id}"));
        Assert.That(polls.Count(r => r.StatusCode == HttpStatusCode.OK), Is.EqualTo(1));
        Assert.That(polls.Count(r => r.StatusCode == HttpStatusCode.NotFound), Is.EqualTo(1));
    }
}
