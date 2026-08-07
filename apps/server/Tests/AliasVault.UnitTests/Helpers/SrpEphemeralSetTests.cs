//-----------------------------------------------------------------------
// <copyright file="SrpEphemeralSetTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Helpers;

using AliasServerDb;
using AliasVault.Api.Helpers;
using AliasVault.Cryptography.Client;
using Microsoft.Extensions.Caching.Memory;
using SecureRemotePassword;

/// <summary>
/// Tests for the server SRP ephemerals an account holds while logins are in flight.
/// </summary>
/// <remarks>
/// Anyone who knows a username can start an exchange for that account. While a single ephemeral was
/// stored, that one request overwrote whatever exchange the account owner had going, and the owner
/// was told their password was wrong. These tests pin the behaviour that stops it.
/// </remarks>
public class SrpEphemeralSetTests
{
    private const string Password = "correct horse battery staple";
    private const string Username = "someone";

    /// <summary>
    /// A proof still validates after somebody else starts an exchange for the same account.
    /// </summary>
    /// <remarks>
    /// This is the defect itself: with one stored ephemeral the second exchange replaced the first,
    /// and the first client's proof no longer matched anything.
    /// </remarks>
    [Test]
    public void ProofSurvivesAnotherExchangeStartingTest()
    {
        var account = new TestAccount();

        // The account owner starts a login and computes their proof.
        var owner = account.BeginExchange();

        // Someone else starts one for the same account before the owner finishes.
        account.BeginExchange();

        Assert.That(account.Validate(owner), Is.Not.Null, "The owner's proof stopped validating because another exchange was started.");
    }

    /// <summary>
    /// Both parties to two concurrent exchanges can complete, in either order.
    /// </summary>
    [Test]
    public void ConcurrentExchangesBothValidateTest()
    {
        var account = new TestAccount();

        var first = account.BeginExchange();
        var second = account.BeginExchange();

        Assert.Multiple(() =>
        {
            Assert.That(account.Validate(second), Is.Not.Null, "The newer exchange failed to validate.");
            Assert.That(account.Validate(first), Is.Not.Null, "The older exchange failed to validate.");
        });
    }

    /// <summary>
    /// Past the limit the oldest ephemeral is dropped and the newest ones keep working.
    /// </summary>
    /// <remarks>
    /// The bound is what keeps an anonymous caller from deciding how much memory the account uses.
    /// Eviction is the accepted cost: pushing an owner's ephemeral out now takes a sustained stream
    /// of requests instead of one.
    /// </remarks>
    [Test]
    public void OldestIsEvictedPastTheLimitTest()
    {
        var account = new TestAccount();

        var oldest = account.BeginExchange();
        var kept = new List<TestExchange>();
        for (var i = 0; i < SrpEphemeralSet.MaxSecretsPerAccount; i++)
        {
            kept.Add(account.BeginExchange());
        }

        Assert.Multiple(() =>
        {
            Assert.That(account.Validate(oldest), Is.Null, "The oldest ephemeral should have been evicted.");
            foreach (var exchange in kept)
            {
                Assert.That(account.Validate(exchange), Is.Not.Null, "An ephemeral within the limit was evicted.");
            }
        });
    }

    /// <summary>
    /// The same proof validates twice without anything being invalidated in between.
    /// </summary>
    /// <remarks>
    /// This is the shape of a login with two-factor authentication: the password proof is checked
    /// once on its own and once alongside the second factor. Dropping the ephemeral on first use
    /// would break every such login, which is why invalidation stays a separate call.
    /// </remarks>
    [Test]
    public void SameProofValidatesTwiceTest()
    {
        var account = new TestAccount();
        var exchange = account.BeginExchange();

        Assert.Multiple(() =>
        {
            Assert.That(account.Validate(exchange), Is.Not.Null, "First validation failed.");
            Assert.That(account.Validate(exchange), Is.Not.Null, "Second validation failed; a 2FA login would break.");
        });
    }

    /// <summary>
    /// Once the exchange is finished the proof is refused, so a captured one cannot be replayed.
    /// </summary>
    [Test]
    public void InvalidationRefusesTheProofTest()
    {
        var account = new TestAccount();
        var exchange = account.BeginExchange();

        Assert.That(account.Validate(exchange), Is.Not.Null, "The exchange should validate before it is finished.");

        account.Invalidate();

        Assert.That(account.Validate(exchange), Is.Null, "A finished exchange must not validate again.");
    }

    /// <summary>
    /// Finishing one exchange also ends the others for that account.
    /// </summary>
    /// <remarks>
    /// Documented rather than desired: it is the behaviour the account already had when one
    /// ephemeral was stored, kept because narrowing it needs the server to know which ephemeral a
    /// proof matched.
    /// </remarks>
    [Test]
    public void InvalidationClearsEveryExchangeTest()
    {
        var account = new TestAccount();
        var first = account.BeginExchange();
        var second = account.BeginExchange();

        account.Invalidate();

        Assert.Multiple(() =>
        {
            Assert.That(account.Validate(first), Is.Null);
            Assert.That(account.Validate(second), Is.Null);
        });
    }

    /// <summary>
    /// Exchanges started in parallel do not lose each other's ephemerals.
    /// </summary>
    /// <remarks>
    /// Two logins arriving at once is exactly the case this change exists for, so the set has to
    /// survive concurrent writers rather than only sequential ones.
    /// </remarks>
    [Test]
    public void ParallelExchangesAreNotLostTest()
    {
        var account = new TestAccount();
        var exchanges = new TestExchange[SrpEphemeralSet.MaxSecretsPerAccount];

        Parallel.For(0, exchanges.Length, i =>
        {
            exchanges[i] = account.BeginExchange();
        });

        Assert.Multiple(() =>
        {
            foreach (var exchange in exchanges)
            {
                Assert.That(account.Validate(exchange), Is.Not.Null, "An ephemeral was lost when exchanges started in parallel.");
            }
        });
    }

    /// <summary>
    /// Every exchange writes the cache entry again, which is what renews its lifetime.
    /// </summary>
    /// <remarks>
    /// The secrets share one cache entry, so its expiry has to be pushed out each time. Written only
    /// when the entry is created, a login started late in the window would inherit whatever was left
    /// of the first one's clock and could expire before the user finished typing their password.
    /// Counting the writes is the observable form of that: IMemoryCache exposes no way to read an
    /// entry's expiry back.
    /// </remarks>
    [Test]
    public void EveryExchangeRewritesTheCacheEntryTest()
    {
        var cache = new WriteCountingCache();
        var account = new TestAccount(cache);

        account.BeginExchange();
        Assert.That(cache.Writes, Is.EqualTo(1), "The first exchange should create the entry.");

        account.BeginExchange();
        Assert.That(cache.Writes, Is.EqualTo(2), "A later exchange must write the entry again so its lifetime restarts.");
    }

    /// <summary>
    /// An account with a real salt and verifier, plus the cache its ephemerals live in.
    /// </summary>
    private sealed class TestAccount
    {
        private readonly IMemoryCache cache;
        private readonly AliasVaultUser user;
        private readonly string passwordHash;

        public TestAccount()
            : this(new MemoryCache(new MemoryCacheOptions()))
        {
        }

        public TestAccount(IMemoryCache cache)
        {
            this.cache = cache;
            var salt = new SrpClient().GenerateSalt().ToUpperInvariant();
            this.passwordHash = Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes(Password));

            var privateKey = Srp.DerivePrivateKey(salt, Username, this.passwordHash);
            var verifier = new SrpClient().DeriveVerifier(privateKey);

            this.user = new AliasVaultUser
            {
                UserName = Username,
                SrpIdentity = Username,
                Vaults =
                [
                    new Vault
                    {
                        Salt = salt,
                        Verifier = verifier,
                        EncryptionType = Defaults.EncryptionType,
                        EncryptionSettings = Defaults.EncryptionSettings,
                        RevisionNumber = 1,
                        VaultBlob = string.Empty,
                        Version = "1.0.0",
                        FileSize = 0,
                    },
                ],
            };
        }

        /// <summary>
        /// Runs the client half of an exchange and stores the matching server ephemeral, the way
        /// the login endpoint does.
        /// </summary>
        /// <returns>The client side of the exchange, ready to be validated.</returns>
        public TestExchange BeginExchange()
        {
            var vault = this.user.Vaults.First();
            var serverEphemeral = Srp.GenerateEphemeralServer(vault.Verifier);
            AuthHelper.StoreSrpEphemeral(this.cache, Username, serverEphemeral.Secret);

            var clientEphemeral = Srp.GenerateEphemeralClient();
            var privateKey = Srp.DerivePrivateKey(vault.Salt, Username, this.passwordHash);
            var clientSession = Srp.DeriveSessionClient(
                privateKey,
                clientEphemeral.Secret,
                serverEphemeral.Public,
                vault.Salt,
                Username);

            return new TestExchange(clientEphemeral.Public, clientSession.Proof);
        }

        /// <summary>
        /// Validates an exchange the way the endpoints do.
        /// </summary>
        /// <param name="exchange">The exchange to validate.</param>
        /// <returns>The server session, or null when the proof is not accepted.</returns>
        public SrpSession? Validate(TestExchange exchange)
        {
            return AuthHelper.ValidateSrpSession(this.cache, this.user, exchange.ClientEphemeralPublic, exchange.ClientSessionProof);
        }

        /// <summary>
        /// Ends every exchange for the account, the way the endpoints do once one finishes.
        /// </summary>
        public void Invalidate()
        {
            AuthHelper.InvalidateSrpSession(this.cache, this.user);
        }
    }

    /// <summary>
    /// A real memory cache that also counts how many times an entry was committed.
    /// </summary>
    private sealed class WriteCountingCache : IMemoryCache
    {
        private readonly MemoryCache inner = new(new MemoryCacheOptions());

        /// <summary>
        /// Gets how many entries were committed to the cache.
        /// </summary>
        public int Writes { get; private set; }

        /// <inheritdoc />
        public ICacheEntry CreateEntry(object key)
        {
            this.Writes++;
            return this.inner.CreateEntry(key);
        }

        /// <inheritdoc />
        public bool TryGetValue(object key, out object? value) => this.inner.TryGetValue(key, out value);

        /// <inheritdoc />
        public void Remove(object key) => this.inner.Remove(key);

        /// <inheritdoc />
        public void Dispose() => this.inner.Dispose();
    }

    /// <summary>
    /// The values a client sends when it completes an exchange.
    /// </summary>
    /// <param name="ClientEphemeralPublic">The client's public ephemeral.</param>
    /// <param name="ClientSessionProof">The client's session proof.</param>
    private sealed record TestExchange(string ClientEphemeralPublic, string ClientSessionProof);
}
