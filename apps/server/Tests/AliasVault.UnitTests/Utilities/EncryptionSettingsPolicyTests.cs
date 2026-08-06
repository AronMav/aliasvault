//-----------------------------------------------------------------------
// <copyright file="EncryptionSettingsPolicyTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Utilities;

using AliasVault.Cryptography.Client;

/// <summary>
/// Tests for the bounds applied to the key derivation parameters a client reports at a password change.
/// Whatever is accepted here is handed back to every client at the next login and is the only thing the
/// new vault can be opened with, so the check is what keeps an account from being moved onto weaker
/// parameters or onto ones no device can afford.
/// </summary>
public class EncryptionSettingsPolicyTests
{
    /// <summary>
    /// The current defaults are acceptable, which is what every up to date client reports.
    /// </summary>
    [Test]
    public void CurrentDefaultsAreAcceptedTest()
    {
        Assert.That(EncryptionSettingsPolicy.IsAcceptable(Defaults.EncryptionType, Defaults.EncryptionSettings), Is.True);
    }

    /// <summary>
    /// The parameters used up to and including 0.25 stay acceptable. Every vault registered before
    /// the default moved holds them, and a client that has not been updated still derives with them.
    /// </summary>
    [Test]
    public void PreviousDefaultsAreStillAcceptedTest()
    {
        const string previousDefaults = """{"DegreeOfParallelism":1,"MemorySize":19456,"Iterations":2}""";

        Assert.That(EncryptionSettingsPolicy.IsAcceptable(Defaults.EncryptionType, previousDefaults), Is.True);
    }

    /// <summary>
    /// Parameters below the minimum are refused. Accepting them would let a password change move an
    /// account onto a cheaper key derivation than it had before.
    /// </summary>
    /// <param name="settings">The settings JSON to check.</param>
    [TestCase("""{"DegreeOfParallelism":1,"MemorySize":8,"Iterations":2}""")]
    [TestCase("""{"DegreeOfParallelism":1,"MemorySize":19455,"Iterations":2}""")]
    [TestCase("""{"DegreeOfParallelism":1,"MemorySize":65536,"Iterations":1}""")]
    [TestCase("""{"DegreeOfParallelism":0,"MemorySize":65536,"Iterations":3}""")]
    public void WeakerThanTheMinimumIsRejectedTest(string settings)
    {
        Assert.That(EncryptionSettingsPolicy.IsAcceptable(Defaults.EncryptionType, settings), Is.False);
    }

    /// <summary>
    /// Parameters above the ceiling are refused, because a vault that costs more to open than a
    /// phone or a browser tab can afford is a vault its owner has lost.
    /// </summary>
    /// <param name="settings">The settings JSON to check.</param>
    [TestCase("""{"DegreeOfParallelism":1,"MemorySize":4194304,"Iterations":3}""")]
    [TestCase("""{"DegreeOfParallelism":1,"MemorySize":65536,"Iterations":100}""")]
    [TestCase("""{"DegreeOfParallelism":64,"MemorySize":65536,"Iterations":3}""")]
    public void StrongerThanTheCeilingIsRejectedTest(string settings)
    {
        Assert.That(EncryptionSettingsPolicy.IsAcceptable(Defaults.EncryptionType, settings), Is.False);
    }

    /// <summary>
    /// A settings value that is not a complete set of parameters is refused rather than completed
    /// from the defaults, since recording a parameter the client never used produces a vault it
    /// cannot open.
    /// </summary>
    /// <param name="settings">The settings value to check.</param>
    [TestCase("")]
    [TestCase("   ")]
    [TestCase("not json")]
    [TestCase("{}")]
    [TestCase("""{"MemorySize":65536,"Iterations":3}""")]
    [TestCase("""{"DegreeOfParallelism":1,"Iterations":3}""")]
    [TestCase("""{"DegreeOfParallelism":1,"MemorySize":65536}""")]
    public void IncompleteOrUnparsableSettingsAreRejectedTest(string settings)
    {
        Assert.Multiple(() =>
        {
            Assert.That(EncryptionSettingsPolicy.IsAcceptable(Defaults.EncryptionType, settings), Is.False);
            Assert.That(EncryptionSettingsPolicy.TryParse(settings, out _), Is.False);
        });
    }

    /// <summary>
    /// Null settings are refused for the same reason an incomplete set is.
    /// </summary>
    [Test]
    public void NullSettingsAreRejectedTest()
    {
        Assert.Multiple(() =>
        {
            Assert.That(EncryptionSettingsPolicy.IsAcceptable(Defaults.EncryptionType, null), Is.False);
            Assert.That(EncryptionSettingsPolicy.TryParse(null, out _), Is.False);
        });
    }

    /// <summary>
    /// Only Argon2id is accepted. The clients implement nothing else, so another value would name
    /// an algorithm no one can derive with.
    /// </summary>
    /// <param name="encryptionType">The encryption type to check.</param>
    [TestCase("")]
    [TestCase("PBKDF2")]
    [TestCase("argon2id")]
    [TestCase(null)]
    public void UnknownEncryptionTypeIsRejectedTest(string? encryptionType)
    {
        Assert.That(EncryptionSettingsPolicy.IsAcceptable(encryptionType, Defaults.EncryptionSettings), Is.False);
    }

    /// <summary>
    /// Parsing reports the values as written rather than the defaults.
    /// </summary>
    [Test]
    public void ParsingReportsTheValuesAsWrittenTest()
    {
        Assert.That(EncryptionSettingsPolicy.TryParse("""{"DegreeOfParallelism":2,"MemorySize":32768,"Iterations":4}""", out var parsed), Is.True);

        Assert.Multiple(() =>
        {
            Assert.That(parsed.DegreeOfParallelism, Is.EqualTo(2));
            Assert.That(parsed.MemorySize, Is.EqualTo(32768));
            Assert.That(parsed.Iterations, Is.EqualTo(4));
        });
    }
}
