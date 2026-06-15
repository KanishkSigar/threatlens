import SwiftUI

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
