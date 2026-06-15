import SwiftUI

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
