import Foundation

class APIService {
    static let shared = APIService()
    // Change this to your local IP address for physical device testing, or 127.0.0.1 for simulator
    let baseURL = "http://127.0.0.1:8000/api"
    
    var token: String? {
        if let data = KeychainHelper.shared.read(service: "com.threatlens.token", account: "user"),
           let savedToken = String(data: data, encoding: .utf8) {
            return savedToken
        }
        return nil
    }
    
    func saveToken(_ newToken: String) {
        if let data = newToken.data(using: .utf8) {
            KeychainHelper.shared.save(data, service: "com.threatlens.token", account: "user")
        }
    }
    
    func clearToken() {
        KeychainHelper.shared.delete(service: "com.threatlens.token", account: "user")
    }
    
    func getRequest(endpoint: String, requiresAuth: Bool = true) -> URLRequest {
        guard let url = URL(string: baseURL + endpoint) else {
            fatalError("Invalid URL")
        }
        var request = URLRequest(url: url)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        if requiresAuth, let token = token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        return request
    }
}
