//-----------------------------------------------------------------------
// <copyright file="FakeEncryptionSettingsTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Helpers;

using AliasVault.Api.Helpers;
using AliasVault.Cryptography.Client;

/// <summary>
/// Tests for the key derivation parameters the login endpoint reports for a username without an account.
/// An account keeps the parameters it was registered under until its password changes, so an instance
/// holds a mix of them once the default moves. Answering with a fixed value would name every account
/// registered under an older default, which is the enumeration this draw exists to prevent.
/// </summary>
public class FakeEncryptionSettingsTests
{
    private const string ServerSecret = "server-secret-used-for-derivation";

    private const string LegacySettings = """{"DegreeOfParallelism":1,"MemorySize":19456,"Iterations":2}""";
    private const string CurrentSettings = """{"DegreeOfParallelism":1,"MemorySize":65536,"Iterations":3}""";

    /// <summary>
    /// The draw is stable per username, so repeating a request cannot reveal that the answer was
    /// invented by watching the reported parameters change between attempts.
    /// </summary>
    [Test]
    public void DrawIsStablePerUsernameTest()
    {
        var distribution = Distribution((LegacySettings, 40), (CurrentSettings, 60));

        var first = AuthHelper.DeriveFakeEncryptionSettings("someone", ServerSecret, distribution);
        var second = AuthHelper.DeriveFakeEncryptionSettings("someone", ServerSecret, distribution);

        Assert.That(second, Is.EqualTo(first));
    }

    /// <summary>
    /// Usernames that differ only in case or surrounding whitespace refer to the same account and
    /// have to be answered identically, matching how a real account resolves.
    /// </summary>
    [Test]
    public void DrawIgnoresUsernameCasingTest()
    {
        var distribution = Distribution((LegacySettings, 40), (CurrentSettings, 60));

        var lower = AuthHelper.DeriveFakeEncryptionSettings("someone", ServerSecret, distribution);
        var mixed = AuthHelper.DeriveFakeEncryptionSettings("  SoMeOne ", ServerSecret, distribution);

        Assert.That(mixed, Is.EqualTo(lower));
    }

    /// <summary>
    /// Only values the instance actually holds are ever reported. Reporting anything else would be
    /// a value no real account on this instance could have.
    /// </summary>
    [Test]
    public void DrawOnlyReturnsValuesInUseTest()
    {
        var distribution = Distribution((LegacySettings, 1), (CurrentSettings, 1));

        for (var i = 0; i < 200; i++)
        {
            var drawn = AuthHelper.DeriveFakeEncryptionSettings($"user{i}", ServerSecret, distribution);

            Assert.That(drawn.EncryptionSettings, Is.AnyOf(LegacySettings, CurrentSettings));
            Assert.That(drawn.EncryptionType, Is.EqualTo(Defaults.EncryptionType));
        }
    }

    /// <summary>
    /// The draw follows how common each value is. A distribution that is almost entirely one value
    /// has to answer with that value almost every time, because a caller who knows the instance is
    /// mostly legacy would otherwise read a rare answer as "no account here".
    /// </summary>
    [Test]
    public void DrawFollowsTheWeightsTest()
    {
        var distribution = Distribution((LegacySettings, 95), (CurrentSettings, 5));

        var legacyCount = 0;
        const int samples = 1000;
        for (var i = 0; i < samples; i++)
        {
            if (AuthHelper.DeriveFakeEncryptionSettings($"user{i}", ServerSecret, distribution).EncryptionSettings == LegacySettings)
            {
                legacyCount++;
            }
        }

        // Bounds are wide enough that a fair draw effectively never fails them, while a draw that
        // ignored the weights entirely (uniform, or always one value) lands well outside.
        Assert.That(legacyCount, Is.InRange((int)(samples * 0.90), (int)(samples * 0.99)));
    }

    /// <summary>
    /// A username cannot be steered towards a particular answer without the server secret: the same
    /// username under a different secret draws independently.
    /// </summary>
    [Test]
    public void DrawDependsOnTheServerSecretTest()
    {
        var distribution = Distribution((LegacySettings, 1), (CurrentSettings, 1));

        var differences = 0;
        for (var i = 0; i < 200; i++)
        {
            var underOne = AuthHelper.DeriveFakeEncryptionSettings($"user{i}", ServerSecret, distribution);
            var underOther = AuthHelper.DeriveFakeEncryptionSettings($"user{i}", "a-different-server-secret", distribution);
            if (underOne != underOther)
            {
                differences++;
            }
        }

        Assert.That(differences, Is.GreaterThan(50));
    }

    /// <summary>
    /// An instance with no vaults has nothing to imitate, so it answers with its own defaults.
    /// </summary>
    [Test]
    public void EmptyDistributionFallsBackToDefaultsTest()
    {
        var drawn = AuthHelper.DeriveFakeEncryptionSettings("someone", ServerSecret, []);

        Assert.Multiple(() =>
        {
            Assert.That(drawn.EncryptionType, Is.EqualTo(Defaults.EncryptionType));
            Assert.That(drawn.EncryptionSettings, Is.EqualTo(Defaults.EncryptionSettings));
        });
    }

    /// <summary>
    /// A distribution whose entries all count zero is treated as empty rather than dividing by it.
    /// </summary>
    [Test]
    public void ZeroWeightedDistributionFallsBackToDefaultsTest()
    {
        var drawn = AuthHelper.DeriveFakeEncryptionSettings("someone", ServerSecret, Distribution((LegacySettings, 0)));

        Assert.That(drawn.EncryptionSettings, Is.EqualTo(Defaults.EncryptionSettings));
    }

    private static List<(string EncryptionType, string EncryptionSettings, int Count)> Distribution(params (string Settings, int Count)[] entries)
    {
        return entries.Select(x => (Defaults.EncryptionType, x.Settings, x.Count)).ToList();
    }
}
