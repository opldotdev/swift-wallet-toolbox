import Foundation

#if canImport(os)
    import os
#endif

/// The toolbox's log, written once where an error is raised.
///
/// An error's user text is kept short on purpose, so the call, host, status and response body that
/// explain it go here instead. The detail is logged as public: it never holds keys, tokens or auth
/// headers, which every caller is responsible for leaving out.
package enum ToolboxLog {
    package static let subsystem = "dev.opl.toolbox"

    package static func error(_ category: String, _ message: @autoclosure () -> String) {
        #if canImport(os)
            let text = message()
            Logger(subsystem: subsystem, category: category).error("\(text, privacy: .public)")
        #endif
    }
}

/// Pure helpers for describing a failed call: the server's own short reason for the user, and a
/// bounded preview of what it sent for the log.
package enum ErrorDetail {
    /// How much of a response body the log keeps.
    package static let logBodyLimit = 2_000
    /// How long a server's reason may be in text shown to a user.
    package static let reasonLimit = 120

    /// The server's own reason for a failure, when it gave a short human-readable one.
    ///
    /// Read from a JSON body's `message`, `description`, `error_description`, `reason`, `detail`
    /// or `error` member (a nested object is searched the same way), or from a short plain-text
    /// body. Markup, long text and bare JSON give nil: they are for the log, not for a person.
    package static func serverReason(_ body: [UInt8]) -> String? {
        guard !body.isEmpty else { return nil }
        // Not JSON is an expected outcome here: the body is then read as plain text below.
        if let object = try? JSONSerialization.jsonObject(
            with: Data(body), options: [.fragmentsAllowed]
        ) {
            return reason(inJSON: object, depth: 0)
        }
        let text = String(decoding: body, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= 300, !text.contains("<"),
              !text.hasPrefix("{"), !text.hasPrefix("[") else { return nil }
        return oneLine(text)
    }

    private static func reason(inJSON object: Any, depth: Int) -> String? {
        if let text = object as? String { return nonEmptyLine(text) }
        guard depth < 3, let members = object as? [String: Any] else { return nil }
        for key in ["message", "description", "error_description", "reason", "detail", "error"] {
            guard let value = members[key] else { continue }
            if let text = value as? String, let line = nonEmptyLine(text) { return line }
            if value is [String: Any], let line = reason(inJSON: value, depth: depth + 1) {
                return line
            }
        }
        if let code = members["code"] as? String, let line = nonEmptyLine(code) { return line }
        return nil
    }

    private static func nonEmptyLine(_ text: String) -> String? {
        let line = oneLine(text)
        return line.isEmpty ? nil : line
    }

    /// Text on one line, whitespace collapsed, cut to `limit` characters with an ellipsis.
    package static func oneLine(_ text: String, limit: Int = ErrorDetail.reasonLimit) -> String {
        let words = text.split(whereSeparator: { $0.isWhitespace || $0.isNewline })
        let line = words.joined(separator: " ")
        guard line.count > limit, limit > 1 else { return line }
        return String(line.prefix(limit - 1)) + "…"
    }

    /// A response body for the log: its text up to `limit` bytes, and its full size when cut.
    package static func bodyPreview(_ body: [UInt8], limit: Int = ErrorDetail.logBodyLimit) -> String {
        if body.isEmpty { return "<empty>" }
        let text = String(decoding: body.prefix(limit), as: UTF8.self)
        return body.count > limit ? "\(text)… (\(body.count) bytes)" : text
    }

    /// `host[:port]/path` with no scheme, query or fragment, since a query can carry a token.
    package static func hostPath(_ url: URL) -> String {
        hostPath(host: url.host, port: url.port, path: url.path)
    }

    package static func hostPath(host: String?, port: Int? = nil, path: String) -> String {
        let authority = (host ?? "?") + (port.map { ":\($0)" } ?? "")
        let cleanPath = path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? ""
        return authority + (cleanPath.hasPrefix("/") ? cleanPath : "/" + cleanPath)
    }
}
