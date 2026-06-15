import SwiftUI

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
