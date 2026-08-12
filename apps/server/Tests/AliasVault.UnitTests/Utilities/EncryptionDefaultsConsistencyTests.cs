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
/// Checks that every generated copy of the Argon2id parameters still matches the source they
/// are generated from.
/// </summary>
/// <remarks>
/// The parameters are declared once, in TypeScript, and generated into the other languages by
/// core/models/scripts/generate-encryption-defaults.cjs. Nothing runs that generator in CI and
/// its output is committed, so a change to the source with no regeneration would leave clients
/// deriving keys the others cannot reproduce. This test is what makes that a failing build
/// rather than a vault that stops opening.
/// </remarks>
public class EncryptionDefaultsConsistencyTests
{
    private const string SourceRelativePath = "core/models/src/defaults/EncryptionDefaults.ts";

    /// <summary>
    /// Each generated artifact, with a pattern per parameter. The dist pair is included because
    /// the TypeScript clients read their values from there rather than from the source: without
    /// it, regenerating C# and Rust while forgetting to rebuild dist would leave the extension
    /// and the mobile app on stale numbers with nothing to catch it.
    /// </summary>
    /// <remarks>
    /// The dist entries check <c>index.d.ts</c>, not the sibling <c>index.js</c> where the
    /// runtime values actually live. Both are written by the same tsup run into a directory that
    /// is wiped first, so the two drifting apart is contrived.
    /// </remarks>
    private static readonly (string RelativePath, string MemoryPattern, string IterationsPattern, string ParallelismPattern, string TypePattern)[] Artifacts =
    [
        (
            "apps/server/Utilities/Cryptography/AliasVault.Cryptography.Client/Argon2Defaults.cs",
            @"Argon2idMemorySize\s*=\s*(\d+)",
            @"Argon2idIterations\s*=\s*(\d+)",
            @"Argon2idDegreeOfParallelism\s*=\s*(\d+)",
            @"EncryptionType\s*=\s*""(\w+)"""),
        (
            "core/rust/src/argon2/defaults.rs",
            @"ARGON2ID_MEMORY_SIZE:\s*u32\s*=\s*(\d+)",
            @"ARGON2ID_ITERATIONS:\s*u32\s*=\s*(\d+)",
            @"ARGON2ID_DEGREE_OF_PARALLELISM:\s*u32\s*=\s*(\d+)",
            @"ENCRYPTION_TYPE:\s*&str\s*=\s*""(\w+)"""),
        (
            "apps/mobile-app/android/app/src/androidTest/java/net/aliasvault/app/EncryptionDefaults.kt",
            @"ARGON2ID_MEMORY_SIZE\s*=\s*(\d+)",
            @"ARGON2ID_ITERATIONS\s*=\s*(\d+)",
            @"ARGON2ID_DEGREE_OF_PARALLELISM\s*=\s*(\d+)",
            @"ENCRYPTION_TYPE\s*=\s*""(\w+)"""),
        (
            "apps/mobile-app/ios/AliasVaultUITests/EncryptionDefaults.swift",
            @"argon2idMemorySize:\s*UInt32\s*=\s*(\d+)",
            @"argon2idIterations:\s*UInt32\s*=\s*(\d+)",
            @"argon2idDegreeOfParallelism:\s*UInt32\s*=\s*(\d+)",
            @"encryptionType:\s*String\s*=\s*""(\w+)"""),
        (
            "apps/browser-extension/src/utils/dist/core/models/defaults/index.d.ts",
            @"ARGON2ID_MEMORY_SIZE\s*=\s*(\d+)",
            @"ARGON2ID_ITERATIONS\s*=\s*(\d+)",
            @"ARGON2ID_DEGREE_OF_PARALLELISM\s*=\s*(\d+)",
            @"ENCRYPTION_TYPE\s*=\s*""(\w+)"""),
        (
            "apps/mobile-app/utils/dist/core/models/defaults/index.d.ts",
            @"ARGON2ID_MEMORY_SIZE\s*=\s*(\d+)",
            @"ARGON2ID_ITERATIONS\s*=\s*(\d+)",
            @"ARGON2ID_DEGREE_OF_PARALLELISM\s*=\s*(\d+)",
            @"ENCRYPTION_TYPE\s*=\s*""(\w+)"""),
    ];

    /// <summary>
    /// The generated files that hold the settings as a string literal. All four escape the
    /// inner quotes the same way, so one expected value covers them.
    /// </summary>
    private static readonly string[] GeneratedFilesHoldingTheSettingsLiteral =
    [
        "apps/server/Utilities/Cryptography/AliasVault.Cryptography.Client/Argon2Defaults.cs",
        "core/rust/src/argon2/defaults.rs",
        "apps/mobile-app/android/app/src/androidTest/java/net/aliasvault/app/EncryptionDefaults.kt",
        "apps/mobile-app/ios/AliasVaultUITests/EncryptionDefaults.swift",
    ];

    /// <summary>
    /// Every generated artifact declares the numbers the source declares.
    /// </summary>
    /// <param name="index">Index into the artifact list, so a mismatch names the file that drifted.</param>
    [Test]
    [TestCase(0)]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    [TestCase(4)]
    [TestCase(5)]
    public void GeneratedArtifactMatchesTheSourceTest(int index)
    {
        var (relativePath, memoryPattern, iterationsPattern, parallelismPattern, typePattern) = Artifacts[index];
        var root = FindRepositoryRoot();
        var source = ReadRepositoryFile(root, SourceRelativePath);
        var artifact = ReadRepositoryFile(root, relativePath);

        var expectedMemory = ReadValue(source, @"ARGON2ID_MEMORY_SIZE\s*=\s*(\d+)", SourceRelativePath, "memory size");
        var expectedIterations = ReadValue(source, @"ARGON2ID_ITERATIONS\s*=\s*(\d+)", SourceRelativePath, "iterations");
        var expectedParallelism = ReadValue(source, @"ARGON2ID_DEGREE_OF_PARALLELISM\s*=\s*(\d+)", SourceRelativePath, "parallelism");
        var expectedType = ReadStringValue(source, @"ENCRYPTION_TYPE\s*=\s*'(\w+)'", SourceRelativePath, "encryption type");

        Assert.Multiple(() =>
        {
            Assert.That(ReadValue(artifact, memoryPattern, relativePath, "memory size"), Is.EqualTo(expectedMemory), $"{relativePath} is stale. Run core/models/build.sh.");
            Assert.That(ReadValue(artifact, iterationsPattern, relativePath, "iterations"), Is.EqualTo(expectedIterations), $"{relativePath} is stale. Run core/models/build.sh.");
            Assert.That(ReadValue(artifact, parallelismPattern, relativePath, "parallelism"), Is.EqualTo(expectedParallelism), $"{relativePath} is stale. Run core/models/build.sh.");
            Assert.That(ReadStringValue(artifact, typePattern, relativePath, "encryption type"), Is.EqualTo(expectedType), $"{relativePath} is stale. Run core/models/build.sh.");
        });
    }

    /// <summary>
    /// The C# defaults expose the same numbers as the source, so the server derives keys with
    /// what the clients were told to use.
    /// </summary>
    [Test]
    public void CSharpDefaultsMatchTheSourceTest()
    {
        var source = ReadRepositoryFile(FindRepositoryRoot(), SourceRelativePath);

        Assert.Multiple(() =>
        {
            Assert.That(Defaults.Argon2IdMemorySize, Is.EqualTo(ReadValue(source, @"ARGON2ID_MEMORY_SIZE\s*=\s*(\d+)", SourceRelativePath, "memory size")));
            Assert.That(Defaults.Argon2IdIterations, Is.EqualTo(ReadValue(source, @"ARGON2ID_ITERATIONS\s*=\s*(\d+)", SourceRelativePath, "iterations")));
            Assert.That(Defaults.Argon2IdDegreeOfParallelism, Is.EqualTo(ReadValue(source, @"ARGON2ID_DEGREE_OF_PARALLELISM\s*=\s*(\d+)", SourceRelativePath, "parallelism")));
        });
    }

    /// <summary>
    /// Every generated file spells the settings string the same way, and it is the string the
    /// source describes.
    /// </summary>
    /// <remarks>
    /// Key order is the one thing stated twice: once in the TypeScript source, once in the
    /// generator. The string is what registration stores against the vault, so a reordering
    /// would change the stored value while every number still agreed. The expected string is
    /// built from the numbers rather than written out, so raising a parameter does not mean
    /// editing this test.
    ///
    /// The generated files hold the string as a literal and are all checked. The two dist
    /// artifacts are not: tsup widens a computed export to `declare const X: string`, leaving
    /// no value to compare. That is safe, because the string there is computed at runtime from
    /// the numbers this class already checks.
    /// </remarks>
    [Test]
    public void SettingsStringIsConsistentEverywhereTest()
    {
        var root = FindRepositoryRoot();
        var source = ReadRepositoryFile(root, SourceRelativePath);

        var keyOrder = ReadSourceKeyOrder(source);
        Assert.That(keyOrder, Is.EqualTo(new[] { "DegreeOfParallelism", "MemorySize", "Iterations" }), "The canonical key order changed in the source but not in the generator.");

        var expected = string.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            "{{\"DegreeOfParallelism\":{0},\"MemorySize\":{1},\"Iterations\":{2}}}",
            ReadValue(source, @"ARGON2ID_DEGREE_OF_PARALLELISM\s*=\s*(\d+)", SourceRelativePath, "parallelism"),
            ReadValue(source, @"ARGON2ID_MEMORY_SIZE\s*=\s*(\d+)", SourceRelativePath, "memory size"),
            ReadValue(source, @"ARGON2ID_ITERATIONS\s*=\s*(\d+)", SourceRelativePath, "iterations"));

        Assert.Multiple(() =>
        {
            Assert.That(Defaults.EncryptionSettings, Is.EqualTo(expected));

            foreach (var relativePath in GeneratedFilesHoldingTheSettingsLiteral)
            {
                var artifact = ReadRepositoryFile(root, relativePath);
                Assert.That(artifact, Does.Contain(expected.Replace("\"", "\\\"")), $"{relativePath} spells the settings string differently. Run core/models/build.sh.");
            }
        });
    }

    /// <summary>
    /// The defaults are within what the server is willing to record, so an up to date client is
    /// never refused by the bounds applied at a password change.
    /// </summary>
    [Test]
    public void DefaultsSatisfyTheServerPolicyTest()
    {
        Assert.That(EncryptionSettingsPolicy.IsAcceptable(Defaults.EncryptionType, Defaults.EncryptionSettings, Defaults.EncryptionSettings), Is.True);
    }

    /// <summary>
    /// Reads the key order out of the JSON.stringify call in the TypeScript source.
    /// </summary>
    private static List<string> ReadSourceKeyOrder(string source)
    {
        var match = Regex.Match(source, @"JSON\.stringify\(\{(.*?)\}\)", RegexOptions.Singleline);
        Assert.That(match.Success, Is.True, $"Could not find the settings literal in {SourceRelativePath}.");

        return Regex.Matches(match.Groups[1].Value, @"(\w+)\s*:")
            .Select(m => m.Groups[1].Value)
            .ToList();
    }

    private static string ReadRepositoryFile(string root, string relativePath)
    {
        var path = Path.Combine(root, relativePath);
        Assert.That(File.Exists(path), Is.True, $"{relativePath} no longer exists; update this test along with the move.");
        return File.ReadAllText(path);
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
    /// Same contract as <see cref="ReadValue"/>, for a pattern whose captured group is a string
    /// rather than a number.
    /// </summary>
    private static string ReadStringValue(string content, string pattern, string relativePath, string what)
    {
        var matches = Regex.Matches(content, pattern);
        Assert.That(matches, Is.Not.Empty, $"Could not find the Argon2id {what} in {relativePath}. The declaration moved or was reworded; update the pattern in this test.");

        var values = matches.Select(m => m.Groups[1].Value).Distinct().ToList();
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
