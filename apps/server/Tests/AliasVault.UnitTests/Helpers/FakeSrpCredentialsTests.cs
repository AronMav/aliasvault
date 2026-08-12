//-----------------------------------------------------------------------
// <copyright file="FakeSrpCredentialsTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Helpers;

using AliasVault.Api.Helpers;
using AliasVault.Cryptography.Client;

/// <summary>
/// Tests for the fake SRP credentials that the login endpoint returns for a username without an account.
/// The login response must not let a caller tell a real account from an unknown one, so every value a
/// caller can observe has to be produced in the same shape a real registration would have produced it in.
/// </summary>
public class FakeSrpCredentialsTests
{
    private const string ServerSecret = "server-secret-used-for-derivation";

    /// <summary>
    /// The same username derives the same values, so repeated attempts cannot be told apart from a real
    /// account by watching the salt change between requests.
    /// </summary>
    [Test]
    public void CredentialsAreStablePerUsernameTest()
    {
        var first = AuthHelper.DeriveFakeSrpCredentials("someone", ServerSecret);
        var second = AuthHelper.DeriveFakeSrpCredentials("someone", ServerSecret);

        Assert.Multiple(() =>
        {
            Assert.That(second.Salt, Is.EqualTo(first.Salt));
            Assert.That(second.Verifier, Is.EqualTo(first.Verifier));
            Assert.That(second.SrpIdentity, Is.EqualTo(first.SrpIdentity));
        });
    }

    /// <summary>
    /// Usernames that only differ in case or surrounding whitespace refer to the same account, so they
    /// must derive the same values as well.
    /// </summary>
    [Test]
    public void CredentialsIgnoreUsernameCasingAndWhitespaceTest()
    {
        var plain = AuthHelper.DeriveFakeSrpCredentials("someone", ServerSecret);
        var decorated = AuthHelper.DeriveFakeSrpCredentials("  SoMeOne ", ServerSecret);

        Assert.Multiple(() =>
        {
            Assert.That(decorated.Salt, Is.EqualTo(plain.Salt));
            Assert.That(decorated.SrpIdentity, Is.EqualTo(plain.SrpIdentity));
        });
    }

    /// <summary>
    /// Different usernames derive different values, matching real accounts which each have their own salt.
    /// </summary>
    [Test]
    public void CredentialsDifferPerUsernameTest()
    {
        var first = AuthHelper.DeriveFakeSrpCredentials("someone", ServerSecret);
        var second = AuthHelper.DeriveFakeSrpCredentials("someone-else", ServerSecret);

        Assert.Multiple(() =>
        {
            Assert.That(second.Salt, Is.Not.EqualTo(first.Salt));
            Assert.That(second.SrpIdentity, Is.Not.EqualTo(first.SrpIdentity));
        });
    }

    /// <summary>
    /// Two servers do not hand out the same fake values for the same username.
    /// </summary>
    [Test]
    public void CredentialsDifferPerServerSecretTest()
    {
        var first = AuthHelper.DeriveFakeSrpCredentials("someone", ServerSecret);
        var second = AuthHelper.DeriveFakeSrpCredentials("someone", "a-different-server-secret");

        Assert.That(second.Salt, Is.Not.EqualTo(first.Salt));
    }

    /// <summary>
    /// Clients generate the salt as uppercase hex of 32 random bytes. A fake salt in any other shape
    /// (a shorter value, or lowercase hex) identifies the account as non-existent on sight.
    /// </summary>
    [Test]
    public void SaltMatchesClientGeneratedFormatTest()
    {
        var credentials = AuthHelper.DeriveFakeSrpCredentials("someone", ServerSecret);

        Assert.Multiple(() =>
        {
            Assert.That(credentials.Salt, Has.Length.EqualTo(64));
            Assert.That(credentials.Salt, Does.Match("^[0-9A-F]{64}$"));
        });
    }

    /// <summary>
    /// Clients generate the SRP identity with crypto.randomUUID()/Guid.NewGuid(), which both produce a
    /// version 4 UUID. The derived identity has to carry the same version and variant nibbles.
    /// </summary>
    [Test]
    public void SrpIdentityMatchesClientGeneratedFormatTest()
    {
        var credentials = AuthHelper.DeriveFakeSrpCredentials("someone", ServerSecret);

        Assert.Multiple(() =>
        {
            Assert.That(Guid.TryParse(credentials.SrpIdentity, out _), Is.True);
            Assert.That(credentials.SrpIdentity, Does.Match("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"));
        });
    }

    /// <summary>
    /// The verifier feeds the server ephemeral in the response, so it has to be a usable SRP verifier of
    /// the same length a real one has.
    /// </summary>
    [Test]
    public void VerifierMatchesRealVerifierFormatTest()
    {
        var credentials = AuthHelper.DeriveFakeSrpCredentials("someone", ServerSecret);

        Assert.Multiple(() =>
        {
            Assert.That(credentials.Verifier, Has.Length.EqualTo(512));
            Assert.That(credentials.Verifier, Does.Match("^[0-9a-f]{512}$"));
        });
    }

    /// <summary>
    /// The derived verifier has to work as the input to the server ephemeral that the login response
    /// actually returns. It is not a real g^x mod N --- computing one would cost a second modular
    /// exponentiation and make an unknown username measurably slower to answer than a known one --- so
    /// this pins that the cheaper value is still accepted by the SRP server.
    /// </summary>
    [Test]
    public void VerifierProducesAServerEphemeralTest()
    {
        var credentials = AuthHelper.DeriveFakeSrpCredentials("someone", ServerSecret);

        var ephemeral = Srp.GenerateEphemeralServer(credentials.Verifier);

        Assert.Multiple(() =>
        {
            Assert.That(ephemeral.Public, Is.Not.Empty);
            Assert.That(ephemeral.Secret, Is.Not.Empty);
        });
    }

    /// <summary>
    /// An oversized username is bounded by the caller, but deriving from one must not throw either.
    /// </summary>
    [Test]
    public void LongUsernameDerivesCredentialsTest()
    {
        var credentials = AuthHelper.DeriveFakeSrpCredentials(new string('a', 1000), ServerSecret);

        Assert.That(credentials.Salt, Does.Match("^[0-9A-F]{64}$"));
    }
}
