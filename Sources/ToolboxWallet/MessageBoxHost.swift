import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Host policy from message-box-client/src/host.ts. Operator-configured hosts
/// may be private; untrusted overlay advertisements may not. Production Swift
/// callers require HTTPS, as does the toolbox's storage transport.
public enum MessageBoxHost {
    public static func configured(_ text: String) throws -> URL {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= 2048,
              var parts = URLComponents(string: text), parts.scheme?.lowercased() == "https",
              let host = parts.host, !host.isEmpty, parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil else { throw MessageBoxError.invalidHost }
        parts.scheme = "https"
        while parts.percentEncodedPath.hasSuffix("/") { parts.percentEncodedPath.removeLast() }
        guard let url = parts.url else { throw MessageBoxError.invalidHost }
        return url
    }

    static func advertised(_ text: String) -> URL? {
        guard let url = try? configured(text), let host = url.host?.lowercased() else { return nil }
        let normalized = host.trimmingCharacters(in: CharacterSet(charactersIn: ".[]"))
        if normalized == "localhost" || normalized == "example.com" ||
            [".localhost", ".local", ".lan", ".home", ".internal", ".test", ".invalid", ".example.com"].contains(where: normalized.hasSuffix) {
            return nil
        }
        if normalized.contains(":") {
            var address = in6_addr()
            guard inet_pton(AF_INET6, normalized, &address) == 1 else { return nil }
            let bytes = withUnsafeBytes(of: address) { Array($0) }
            if bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes[15] <= 1 { return nil }
            if bytes[0] & 0xfe == 0xfc || (bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80)
                || bytes[0] == 0xff || Array(bytes.prefix(4)) == [0x20, 0x01, 0x0d, 0xb8]
                || (bytes.prefix(10).allSatisfy({ $0 == 0 }) && bytes[10] == 0xff && bytes[11] == 0xff) { return nil }
        } else {
            let components = normalized.split(separator: ".", omittingEmptySubsequences: false)
            // Reject non-canonical numeric hosts that URLSession may interpret as
            // loopback shorthand or hexadecimal/octal IPv4 addresses.
            if components.allSatisfy({ Int($0) != nil || $0.hasPrefix("0x") }) {
                let bytes = components.compactMap { Int($0) }
                guard bytes.count == 4, bytes.allSatisfy({ (0...255).contains($0) }),
                      !components.contains(where: { $0.count > 1 && $0.hasPrefix("0") }) else { return nil }
                let first = bytes[0], second = bytes[1]
                if first == 0 || first == 10 || first == 127 || first >= 224
                    || (first == 100 && (64...127).contains(second))
                    || (first == 169 && second == 254)
                    || (first == 172 && (16...31).contains(second))
                    || (first == 192 && second == 0 && [0, 2].contains(bytes[2]))
                    || (first == 192 && second == 168)
                    || (first == 198 && (second == 18 || second == 19 || (second == 51 && bytes[2] == 100)))
                    || (first == 203 && second == 0 && bytes[2] == 113) { return nil }
            }
        }
        return url
    }
}
