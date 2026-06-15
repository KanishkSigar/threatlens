import Foundation
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
