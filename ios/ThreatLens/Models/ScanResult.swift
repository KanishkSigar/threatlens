import Foundation

struct ScanRequest: Codable {
    let url: String?
    let emailContent: String?
    let subject: String?
    
    enum CodingKeys: String, CodingKey {
        case url
        case emailContent = "email_content"
        case subject
    }
}

struct ScanResult: Codable, Identifiable {
    let id: String
    let scanType: String
    let riskScore: Double
    let verdict: String
    let confidence: Double
    let detailsJson: String?
    let createdAt: String
    
    enum CodingKeys: String, CodingKey {
        case id
        case scanType = "scan_type"
        case riskScore = "risk_score"
        case verdict
        case confidence
        case detailsJson = "details_json"
        case createdAt = "created_at"
    }
}

struct ScanHistoryResponse: Codable {
    let scans: [ScanResult]
    let total: Int
}
