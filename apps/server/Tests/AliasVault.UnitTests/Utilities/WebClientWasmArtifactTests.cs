//-----------------------------------------------------------------------
// <copyright file="WebClientWasmArtifactTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Utilities;

using System.Text.RegularExpressions;

/// <summary>
/// Pins which Rust WASM build the Blazor web client is given.
/// </summary>
/// <remarks>
/// The core is built twice: dist/wasm for the browser extension, and dist/wasm-web with the kdbx
/// feature for the web client, which is what makes importing a KeePass database possible. Three
/// separate places choose between them -- the build script and each of the two Dockerfiles -- and
/// nothing else notices when they disagree, because the E2E suite runs against a locally built
/// client rather than the image. That is how the released images once shipped the extension build
/// and broke .kdbx import in production only.
/// </remarks>
public class WebClientWasmArtifactTests
{
    private const string BlazorWasmDirectory = "wasm-web";

    private static readonly string[] FilesThatChooseTheArtifact =
    [
        "apps/server/AliasVault.Client/Dockerfile",
        "dockerfiles/all-in-one/Dockerfile",
        "core/rust/build.sh",
    ];

    /// <summary>
    /// Every place that copies a WASM build into the web client's wwwroot takes the kdbx-enabled one.
    /// </summary>
    /// <param name="relativePath">Path of the file to check, relative to the repository root.</param>
    [TestCaseSource(nameof(FilesThatChooseTheArtifact))]
    public void WebClientIsGivenTheKdbxWasmBuild(string relativePath)
    {
        var content = ReadRepositoryFile(relativePath);

        // Every line that writes into the Blazor client's wasm directory has to read from wasm-web.
        var writesToBlazorClient = content
            .Split('\n')
            .Where(line => line.Contains("AliasVault.Client/wwwroot/wasm", StringComparison.Ordinal)
                || line.Contains("BLAZOR_CLIENT_DIST", StringComparison.Ordinal))
            .Where(line => line.Contains("cp ", StringComparison.Ordinal) || line.Contains("$WASM", StringComparison.Ordinal))
            .ToList();

        Assert.That(writesToBlazorClient, Is.Not.Empty, $"{relativePath} no longer copies a WASM build to the web client; update this test along with the move.");

        foreach (var line in writesToBlazorClient)
        {
            var readsExtensionBuild = Regex.IsMatch(line, @"dist/wasm/") || Regex.IsMatch(line, @"\$WASM_DIR\b");
            Assert.That(
                readsExtensionBuild,
                Is.False,
                $"{relativePath} gives the web client the browser-extension WASM build, which has no kdbx support:{Environment.NewLine}{line.Trim()}");
        }
    }

    /// <summary>
    /// The kdbx-enabled build is actually produced, so the paths above have something to copy.
    /// </summary>
    [Test]
    public void BuildScriptProducesTheKdbxWasmBuild()
    {
        var buildScript = ReadRepositoryFile("core/rust/build.sh");

        Assert.Multiple(() =>
        {
            Assert.That(buildScript, Does.Contain(BlazorWasmDirectory), "build.sh no longer names the wasm-web output directory.");
            Assert.That(buildScript, Does.Match(@"--features\s+wasm,kdbx"), "build.sh no longer builds a WASM artifact with the kdbx feature.");
        });
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        var path = Path.Combine(FindRepositoryRoot(), relativePath);
        Assert.That(File.Exists(path), Is.True, $"{relativePath} no longer exists; update this test along with the move.");
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Walks up from the test binary to the directory holding the repository.
    /// </summary>
    /// <returns>The repository root directory.</returns>
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
