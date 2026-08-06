//-----------------------------------------------------------------------
// <copyright file="EncryptionDefaultsConsistencyTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Utilities;

using System.Text.RegularExpressions;
using AliasVault.Cryptography.Client;

/// <summary>
/// Checks that every client declares the same Argon2id parameters.
/// </summary>
/// <remarks>
/// The parameters are declared separately in each client because they are written in five languages,
/// and there is no build step tying them together. They are not free to differ: a vault registered by
/// one client has to be openable by all of them, so a value that drifts in one place produces a key
/// the others cannot reproduce, which reads to the user as a correct password being rejected.
/// This test is the tie.
/// </remarks>
public class EncryptionDefaultsConsistencyTests
{
    /// <summary>
    /// Each declaration, as a path relative to the repository root with a pattern per parameter.
    /// </summary>
    private static readonly (string RelativePath, string MemoryPattern, string IterationsPattern, string ParallelismPattern)[] Declarations =
    [
        (
            "apps/browser-extension/src/utils/auth/SrpAuthService.ts",
            @"MemorySize:\s*(\d+)",
            @"Iterations:\s*(\d+)",
            @"DegreeOfParallelism:\s*(\d+)"),
        (
            "apps/browser-extension/src/utils/EncryptionUtility.ts",
            @"""MemorySize"":(\d+)",
            @"""Iterations"":(\d+)",
            @"""DegreeOfParallelism"":(\d+)"),
        (
            "apps/browser-extension/tests/helpers/test-api.ts",
            @"MemorySize:\s*(\d+)",
            @"Iterations:\s*(\d+)",
            @"DegreeOfParallelism:\s*(\d+)"),
        (
            "apps/mobile-app/utils/EncryptionUtility.ts",
            @"MemorySize:\s*(\d+)",
            @"Iterations:\s*(\d+)",
            @"DegreeOfParallelism:\s*(\d+)"),
        (
            "apps/mobile-app/android/app/src/androidTest/java/net/aliasvault/app/TestConfiguration.kt",
            @"MEMORY_SIZE\s*=\s*(\d+)",
            @"ITERATIONS\s*=\s*(\d+)",
            @"PARALLELISM\s*=\s*(\d+)"),
        (
            "apps/mobile-app/ios/AliasVaultUITests/TestUserRegistration.swift",
            @"memorySize:\s*UInt32\s*=\s*(\d+)",
            @"iterations:\s*UInt32\s*=\s*(\d+)",
            @"parallelism:\s*UInt32\s*=\s*(\d+)"),
        (
            "core/rust/src/argon2/mod.rs",
            @"DEFAULT_MEMORY_KIB:\s*u32\s*=\s*(\d+)",
            @"DEFAULT_ITERATIONS:\s*u32\s*=\s*(\d+)",
            @"DEFAULT_PARALLELISM:\s*u32\s*=\s*(\d+)"),
    ];

    /// <summary>
    /// Every client declares the same values as the C# defaults.
    /// </summary>
    /// <param name="index">Index into the declaration list, so a mismatch names the file that drifted.</param>
    [Test]
    [TestCase(0)]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    [TestCase(4)]
    [TestCase(5)]
    [TestCase(6)]
    public void ClientDeclaresTheSameParametersTest(int index)
    {
        var (relativePath, memoryPattern, iterationsPattern, parallelismPattern) = Declarations[index];
        var path = Path.Combine(FindRepositoryRoot(), relativePath);

        Assert.That(File.Exists(path), Is.True, $"{relativePath} no longer exists; update this test along with the move.");

        var content = File.ReadAllText(path);

        Assert.Multiple(() =>
        {
            Assert.That(ReadValue(content, memoryPattern, relativePath, "memory size"), Is.EqualTo(Defaults.Argon2IdMemorySize), $"{relativePath} declares a different Argon2id memory size than Defaults.cs.");
            Assert.That(ReadValue(content, iterationsPattern, relativePath, "iterations"), Is.EqualTo(Defaults.Argon2IdIterations), $"{relativePath} declares a different Argon2id iteration count than Defaults.cs.");
            Assert.That(ReadValue(content, parallelismPattern, relativePath, "parallelism"), Is.EqualTo(Defaults.Argon2IdDegreeOfParallelism), $"{relativePath} declares a different Argon2id parallelism than Defaults.cs.");
        });
    }

    /// <summary>
    /// The defaults are at least what the server is willing to accept, so an up to date client is
    /// never refused by the bounds applied at a password change.
    /// </summary>
    [Test]
    public void DefaultsSatisfyTheServerPolicyTest()
    {
        Assert.That(EncryptionSettingsPolicy.IsAcceptable(Defaults.EncryptionType, Defaults.EncryptionSettings, Defaults.EncryptionSettings), Is.True);
    }

    private static int ReadValue(string content, string pattern, string relativePath, string what)
    {
        var matches = Regex.Matches(content, pattern);
        Assert.That(matches, Is.Not.Empty, $"Could not find the Argon2id {what} in {relativePath}. The declaration moved or was reworded; update the pattern in this test.");

        var values = matches.Select(m => int.Parse(m.Groups[1].Value)).Distinct().ToList();
        Assert.That(values, Has.Count.EqualTo(1), $"{relativePath} declares more than one Argon2id {what}: {string.Join(", ", values)}.");

        return values[0];
    }

    /// <summary>
    /// Walks up from the test binary to the directory holding the repository.
    /// </summary>
    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")) || File.Exists(Path.Combine(directory.FullName, ".git")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the repository root from the test output directory.");
    }
}
