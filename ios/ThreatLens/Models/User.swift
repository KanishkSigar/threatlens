import Foundation

struct User: Codable, Identifiable {
    let id: String
    let email: String
    let username: String
    let createdAt: String?
    
    enum CodingKeys: String, CodingKey {
        case id
        case email
        case username
        case createdAt = "created_at"
    }
}

struct TokenResponse: Codable {
    let accessToken: String
    let userId: String
    let username: String
    
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case userId = "user_id"
        case username
    }
}
