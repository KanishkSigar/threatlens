import os

base_dir = "ios/ThreatLens"

files = {
    f"{base_dir}/ThreatLensApp.swift": """import SwiftUI

@main
struct ThreatLensApp: App {
    @StateObject private var authViewModel = AuthViewModel()
    
    var body: some Scene {
        WindowGroup {
            if authViewModel.isAuthenticated {
                MainTabView()
                    .environmentObject(authViewModel)
            } else {
                LoginView()
                    .environmentObject(authViewModel)
            }
        }
    }
}
""",
    f"{base_dir}/Views/MainTabView.swift": """import SwiftUI

struct MainTabView: View {
    var body: some View {
        TabView {
            HomeDashboardView()
                .tabItem {
                    Label("Home", systemImage: "house")
                }
            
            ScannerView()
                .tabItem {
                    Label("Scan", systemImage: "qrcode.viewfinder")
                }
                
            HistoryView()
                .tabItem {
                    Label("History", systemImage: "clock")
                }
                
            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
        }
        .tint(.blue)
    }
}
""",
    f"{base_dir}/Models/User.swift": """import Foundation

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
""",
    f"{base_dir}/Models/ScanResult.swift": """import Foundation

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
""",
    f"{base_dir}/Services/KeychainHelper.swift": """import Foundation
import Security

class KeychainHelper {
    static let shared = KeychainHelper()
    
    func save(_ data: Data, service: String, account: String) {
        let query = [
            kSecValueData: data,
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ] as CFDictionary
        
        SecItemDelete(query)
        SecItemAdd(query, nil)
    }
    
    func read(service: String, account: String) -> Data? {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ] as CFDictionary
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query, &dataTypeRef)
        
        if status == errSecSuccess {
            return dataTypeRef as? Data
        }
        return nil
    }
    
    func delete(service: String, account: String) {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ] as CFDictionary
        
        SecItemDelete(query)
    }
}
""",
    f"{base_dir}/Services/APIService.swift": """import Foundation

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
            request.setValue("Bearer \\(token)", forHTTPHeaderField: "Authorization")
        }
        return request
    }
}
""",
    f"{base_dir}/ViewModels/AuthViewModel.swift": """import Foundation
import Combine

class AuthViewModel: ObservableObject {
    @Published var isAuthenticated: Bool = false
    @Published var currentUser: User?
    @Published var errorMessage: String?
    @Published var isLoading: Bool = false
    
    init() {
        checkAuth()
    }
    
    func checkAuth() {
        if APIService.shared.token != nil {
            isAuthenticated = true
            fetchProfile()
        }
    }
    
    func fetchProfile() {
        let request = APIService.shared.getRequest(endpoint: "/auth/me")
        
        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                if let data = data, let user = try? JSONDecoder().decode(User.self, from: data) {
                    self?.currentUser = user
                } else {
                    self?.logout()
                }
            }
        }.resume()
    }
    
    func logout() {
        APIService.shared.clearToken()
        isAuthenticated = false
        currentUser = nil
    }
}
""",
    f"{base_dir}/Views/LoginView.swift": """import SwiftUI

struct LoginView: View {
    @EnvironmentObject var authViewModel: AuthViewModel
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                Text("ThreatLens")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                    
                Text("Login placeholder")
            }
            .navigationTitle("Login")
        }
    }
}
""",
    f"{base_dir}/Views/RegisterView.swift": """import SwiftUI

struct RegisterView: View {
    var body: some View {
        VStack {
            Text("Register placeholder")
        }
        .navigationTitle("Register")
    }
}
""",
    f"{base_dir}/Views/HomeDashboardView.swift": """import SwiftUI

struct HomeDashboardView: View {
    var body: some View {
        NavigationView {
            VStack {
                Text("Dashboard placeholder")
            }
            .navigationTitle("Dashboard")
        }
    }
}
""",
    f"{base_dir}/Views/ScannerView.swift": """import SwiftUI

struct ScannerView: View {
    var body: some View {
        NavigationView {
            VStack {
                Text("Scanner placeholder")
            }
            .navigationTitle("Scan")
        }
    }
}
""",
    f"{base_dir}/Views/ScanResultView.swift": """import SwiftUI

struct ScanResultView: View {
    var body: some View {
        VStack {
            Text("Scan Result placeholder")
        }
        .navigationTitle("Result")
    }
}
""",
    f"{base_dir}/Views/HistoryView.swift": """import SwiftUI

struct HistoryView: View {
    var body: some View {
        NavigationView {
            VStack {
                Text("History placeholder")
            }
            .navigationTitle("History")
        }
    }
}
""",
    f"{base_dir}/Views/SettingsView.swift": """import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var authViewModel: AuthViewModel
    
    var body: some View {
        NavigationView {
            List {
                Button("Log Out", role: .destructive) {
                    authViewModel.logout()
                }
            }
            .navigationTitle("Settings")
        }
    }
}
"""
}

for filepath, content in files.items():
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        f.write(content)

print(f"Scaffolded {len(files)} files successfully.")
