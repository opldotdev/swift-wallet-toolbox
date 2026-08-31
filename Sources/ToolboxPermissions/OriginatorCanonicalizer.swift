import Foundation

public enum OriginatorCanonicalizer {
    /// Matches current wallet-toolbox behavior: lowercase host, retain non-default ports, and drop
    /// HTTP 80 / HTTPS 443. Origin authentication remains the host transport's responsibility.
    public static func normalize(_ originator: String) -> String {
        let trimmed = originator.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }

        let hasScheme = trimmed.range(
            of: #"^[A-Za-z][A-Za-z0-9+.-]*://"#,
            options: .regularExpression
        ) != nil
        let candidate = hasScheme ? trimmed : "https://\(trimmed)"
        if let components = URLComponents(string: candidate),
           let parsedHost = components.host?.lowercased(),
           !parsedHost.isEmpty {
            // Foundation includes the brackets in `host` on some Darwin releases; WHATWG URL's
            // `hostname` does too in current JavaScript engines. Strip once before rendering so
            // the persisted identity is stable across platforms.
            let host = parsedHost.hasPrefix("[") && parsedHost.hasSuffix("]")
                ? String(parsedHost.dropFirst().dropLast())
                : parsedHost
            let renderedHost = host.contains(":") ? "[\(host)]" : host
            guard let port = components.port else { return renderedHost }
            let scheme = components.scheme?.lowercased()
            let isDefault = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
            return isDefault ? renderedHost : "\(renderedHost):\(port)"
        }

        return trimmed.lowercased()
    }
}
