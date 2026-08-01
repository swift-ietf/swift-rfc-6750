// MARK: - Query Item

extension RFC_6750 {
    /// A name-value pair representing a URI query parameter.
    ///
    /// Replaces Foundation's `URLQueryItem` for Foundation-free operation.
    public struct QueryItem: Sendable, Equatable, Hashable {
        /// The query parameter name
        public let name: String

        /// The query parameter value (nil if absent)
        public let value: String?

        /// Creates a query item
        /// - Parameters:
        ///   - name: The parameter name
        ///   - value: The parameter value
        public init(name: String, value: String?) {
            self.name = name
            self.value = value
        }
    }
}
