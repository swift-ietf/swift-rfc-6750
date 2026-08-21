extension RFC_6750 {

    public struct QueryItem: Sendable, Equatable, Hashable {

        public let name: String

        public let value: String?

        public init(name: String, value: String?) {
            self.name = name
            self.value = value
        }
    }
}
