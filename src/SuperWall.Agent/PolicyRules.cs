using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class PolicyRules
{
    private static readonly IReadOnlyDictionary<string, string[]> CategoryDomains =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["adult"] = new[] { "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "redtube.com", "youporn.com", "spankbang.com" },
            ["gambling"] = new[] { "bet365.com", "betfair.com", "pokerstars.com", "williamhill.com", "unibet.com" },
            ["drugs"] = new[] { "erowid.org", "leafly.com", "weedmaps.com" },
            ["violence"] = new[] { "documentingreality.com", "bestgore.fun" },
            ["social"] = new[] { "tiktok.com", "instagram.com", "facebook.com", "snapchat.com", "x.com", "twitter.com", "reddit.com" },
            ["gaming"] = new[] { "roblox.com", "twitch.tv", "steamcommunity.com", "epicgames.com", "discord.com" },
            ["video"] = new[] { "youtube.com", "youtu.be", "netflix.com" },
            ["phishing"] = new[] { "phishtank.org" }
        };

    public static IReadOnlyCollection<string> GetBlockedDomains(SuperWallPolicy policy)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in policy.BlockedDomains ?? new())
            AddDomain(set, domain);

        foreach (var category in policy.BlockedCategories ?? new())
        {
            if (!CategoryDomains.TryGetValue(category, out var domains)) continue;
            foreach (var domain in domains) AddDomain(set, domain);
        }

        return set;
    }

    public static bool IsDomainBlocked(SuperWallPolicy policy, string host)
    {
        host = NormalizeHost(host);
        if (host.Length == 0) return false;

        foreach (var allowed in policy.AllowedDomains ?? new())
        {
            var normalized = NormalizeHost(allowed);
            if (normalized.Length > 0 && (host.Equals(normalized, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + normalized, StringComparison.OrdinalIgnoreCase)))
                return false;
        }

        return GetBlockedDomains(policy).Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
    }

    public static string NormalizeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return string.Empty;
        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (host.Contains(':')) host = host.Split(':', 2)[0];
        return host;
    }

    private static void AddDomain(HashSet<string> set, string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return;
        var normalized = NormalizeHost(domain);
        if (IsValidDomain(normalized)) set.Add(normalized);
    }

    private static bool IsValidDomain(string domain) => domain.Length is > 0 and <= 253 && domain.Contains('.') && domain.All(c => char.IsLetterOrDigit(c) || c is '.' or '-');
}
