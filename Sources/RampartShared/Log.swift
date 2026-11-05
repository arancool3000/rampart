import Foundation
import os

public enum RLog {
    public static func logger(_ category: String) -> Logger { Logger(subsystem: Product.bundlePrefix, category: category) }
}
