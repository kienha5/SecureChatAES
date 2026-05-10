#define NOMINMAX

#include "../Common/pch.h"
#include "app_state.h"          
#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "network_ops.h"
#include "network_thread.h"
#include <d3d11.h>
#include <thread>
#include <algorithm>

// Chi extern nhung gi D3D11 can
extern ID3D11Device* g_pd3dDevice;
extern ID3D11DeviceContext* g_pd3dDeviceCtx;
extern IDXGISwapChain* g_pSwapChain;
extern ID3D11RenderTargetView* g_mainRTV;

// ─── Color scheme ─────────────────────────────────────────────
static void applyTheme() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 6.0f;
    s.FrameRounding = 4.0f;
    s.ScrollbarRounding = 4.0f;
    s.GrabRounding = 4.0f;
    s.WindowPadding = { 12, 12 };
    s.FramePadding = { 8, 5 };
    s.ItemSpacing = { 8, 6 };

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg] = { 0.10f, 0.12f, 0.15f, 1.0f };
    c[ImGuiCol_ChildBg] = { 0.08f, 0.09f, 0.12f, 1.0f };
    c[ImGuiCol_Header] = { 0.20f, 0.45f, 0.70f, 0.6f };
    c[ImGuiCol_HeaderHovered] = { 0.25f, 0.55f, 0.85f, 0.8f };
    c[ImGuiCol_Button] = { 0.20f, 0.45f, 0.70f, 0.8f };
    c[ImGuiCol_ButtonHovered] = { 0.25f, 0.55f, 0.85f, 1.0f };
    c[ImGuiCol_ButtonActive] = { 0.15f, 0.35f, 0.60f, 1.0f };
    c[ImGuiCol_FrameBg] = { 0.15f, 0.17f, 0.22f, 1.0f };
    c[ImGuiCol_FrameBgHovered] = { 0.20f, 0.23f, 0.30f, 1.0f };
    c[ImGuiCol_TitleBg] = { 0.08f, 0.09f, 0.12f, 1.0f };
    c[ImGuiCol_TitleBgActive] = { 0.12f, 0.28f, 0.48f, 1.0f };
    c[ImGuiCol_Tab] = { 0.12f, 0.14f, 0.18f, 1.0f };
    c[ImGuiCol_TabHovered] = { 0.20f, 0.45f, 0.70f, 1.0f };
    c[ImGuiCol_TabActive] = { 0.15f, 0.35f, 0.60f, 1.0f };
    c[ImGuiCol_Separator] = { 0.20f, 0.23f, 0.30f, 1.0f };
    c[ImGuiCol_ScrollbarBg] = { 0.08f, 0.09f, 0.12f, 1.0f };
    c[ImGuiCol_ScrollbarGrab] = { 0.20f, 0.45f, 0.70f, 0.8f };
    c[ImGuiCol_CheckMark] = { 0.25f, 0.75f, 0.45f, 1.0f };
    c[ImGuiCol_Text] = { 0.90f, 0.92f, 0.95f, 1.0f };
    c[ImGuiCol_TextDisabled] = { 0.45f, 0.48f, 0.55f, 1.0f };
    c[ImGuiCol_PopupBg] = { 0.10f, 0.12f, 0.15f, 0.98f };
}

// ─── Login Screen ─────────────────────────────────────────────
static void renderLoginScreen() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos({ io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f },
        ImGuiCond_Always, { 0.5f, 0.5f });
    ImGui::SetNextWindowSize({ 420, 0 }, ImGuiCond_Always);

    ImGui::Begin("##login", nullptr,
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove);

    // Title
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f, 0.75f, 0.95f, 1.0f));
    float titleW = ImGui::CalcTextSize("SECURE CHAT").x;
    ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - titleW) * 0.5f);
    ImGui::Text("SECURE CHAT");
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.60f, 0.65f, 1.0f));
    float subW = ImGui::CalcTextSize("PKI + Kerberos + E2EE").x;
    ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - subW) * 0.5f);
    ImGui::Text("PKI + Kerberos + E2EE");
    ImGui::PopStyleColor();
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // Server IP
    ImGui::Text("Server IP");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##ip", g_app.serverIP, sizeof(g_app.serverIP));
    ImGui::Spacing();

    // Username / Password
    ImGui::Text("Username");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##user", g_app.username, sizeof(g_app.username));

    ImGui::Text("Password");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##pass", g_app.password, sizeof(g_app.password),
        ImGuiInputTextFlags_Password);
    ImGui::Spacing();

    // Tabs: Login / Register
    if (ImGui::BeginTabBar("##mode")) {
        if (ImGui::BeginTabItem("Login")) {
            g_app.isRegistering = false;
            ImGui::Spacing();
            if (ImGui::Button("Login", { -1, 36 })) {
                std::string user(g_app.username);
                std::string pass(g_app.password);
                std::string ip(g_app.serverIP);
                g_app.statusMsg = "Logging in...";
                g_app.statusIsOk = true;

                std::thread([user, pass, ip]() {
                    auto logCb = [](const std::string& m, bool err) { addLog(m, err); };
                    bool ok = doLogin(
                        user, pass, ip,
                        g_app.Kc, g_app.Kc_tgs,
                        g_app.ticket_tgs_b64, g_app.iv_tgt_b64,
                        g_app.Kc_v, g_app.ticket_v_b64, g_app.iv_tv_b64,
                        g_app.chatSSL, g_app.chatCtx,
                        logCb
                    );
                    if (ok) {
                        g_app.myUsername = user;
                        g_app.statusMsg = "Logged in!";
                        g_app.statusIsOk = true;
                        g_app.connected = true;
                        g_app.screen = AppScreen::MAIN;
                    }
                    else {
                        g_app.statusMsg = "Login failed";
                        g_app.statusIsOk = false;
                    }
                    }).detach();
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Register")) {
            g_app.isRegistering = true;
            ImGui::Spacing();
            ImGui::TextWrapped("First time? Register in 3 steps:");
            ImGui::Spacing();

            if (ImGui::Button("1. Get Certificate (RA)", { -1, 30 })) {
                std::string user(g_app.username);
                std::string ip(g_app.serverIP);
                std::thread([user, ip]() {
                    auto logCb = [](const std::string& m, bool err) { addLog(m, err); };
                    doRegisterCert(user, ip, logCb);
                    }).detach();
            }
            ImGui::Spacing();

            if (ImGui::Button("2. Register Account (Chat Server)", { -1, 30 })) {
                std::string user(g_app.username);
                std::string ip(g_app.serverIP);
                std::thread([user, ip]() {
                    auto logCb = [](const std::string& m, bool err) { addLog(m, err); };
                    doRegisterAccount(user, ip, logCb);
                    }).detach();
            }
            ImGui::Spacing();

            if (ImGui::Button("3. Register KDC", { -1, 30 })) {
                std::string user(g_app.username);
                std::string pass(g_app.password);
                std::string ip(g_app.serverIP);
                std::thread([user, pass, ip]() {
                    auto logCb = [](const std::string& m, bool err) { addLog(m, err); };
                    doRegisterKDC(user, pass, ip, g_app.Kc, logCb);
                    }).detach();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // Status
    ImVec4 statusColor = g_app.statusIsOk ?
        ImVec4(0.25f, 0.75f, 0.45f, 1.0f) :
        ImVec4(0.90f, 0.35f, 0.35f, 1.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, statusColor);
    ImGui::TextWrapped("%s", g_app.statusMsg.c_str());
    ImGui::PopStyleColor();

    // Log panel nho
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.06f, 0.07f, 0.09f, 1.0f));
    ImGui::BeginChild("##loginlog", { 0, 100 }, true);
    {
        std::lock_guard<std::mutex> lock(g_app.logMutex);
        for (auto& [msg, err] : g_app.logs) {
            ImVec4 col = err ?
                ImVec4(0.90f, 0.40f, 0.40f, 1.0f) :
                ImVec4(0.60f, 0.85f, 0.60f, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, col);
            ImGui::TextWrapped("%s", msg.c_str());
            ImGui::PopStyleColor();
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::End();
}

// ─── Main Chat Screen ─────────────────────────────────────────
static void renderChatScreen() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos({ 0, 0 });
    ImGui::SetNextWindowSize(io.DisplaySize);

    ImGui::Begin("##main", nullptr,
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoBringToFrontOnFocus);

    // ── Header ────────────────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f, 0.75f, 0.95f, 1.0f));
    ImGui::Text("SECURE CHAT");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f, 0.75f, 0.45f, 1.0f));
    ImGui::Text("  [E2EE]  Logged in as: %s", g_app.myUsername.c_str());
    ImGui::PopStyleColor();
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 80);
    if (ImGui::SmallButton("Logout")) {
        if (g_app.chatSSL) {
            int s = SSL_get_fd(g_app.chatSSL);
            Network::closeConnection(g_app.chatSSL, s);
            g_app.chatSSL = nullptr;
        }
        g_app.connected = false;
        g_app.chatReady = false;
        g_app.screen = AppScreen::LOGIN;
        g_app.messages.clear();
        g_app.logs.clear();
        memset(g_app.username, 0, sizeof(g_app.username));
        memset(g_app.password, 0, sizeof(g_app.password));
    }
    ImGui::Separator();

    float totalH = ImGui::GetContentRegionAvail().y;
    float logH = 120.0f;
    float inputH = 50.0f;
    float targetBarH = 38.0f;
    float chatH = totalH - logH - inputH - targetBarH - 30.0f;

    // ── Target user bar ───────────────────────────────────────
    ImGui::Text("Chat with:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::InputText("##target", g_app.targetUser, sizeof(g_app.targetUser));
    ImGui::SameLine();

    if (!g_app.chatReady) {
        if (ImGui::Button("Start E2EE Session")) {
            startNetworkThread(true);   // asInitiator = true
        }
        ImGui::SameLine();
        if (ImGui::Button("Wait for Session")) {
            startNetworkThread(false);  // asInitiator = false
        }
    }

    else {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f, 0.85f, 0.45f, 1.0f));
        ImGui::Text("E2EE Active");
        ImGui::PopStyleColor();
    }

    ImGui::Separator();

    // ── Chat messages ─────────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.07f, 0.08f, 0.11f, 1.0f));
    ImGui::BeginChild("##chat", { 0, chatH }, false);
    {
        std::lock_guard<std::mutex> lock(g_app.msgMutex);
        for (auto& msg : g_app.messages) {
            if (msg.isMe) {
                // Tin nhan cua minh - can phai
                std::string label = "[Me]: " + msg.text;
                float tw = ImGui::CalcTextSize(label.c_str()).x + 16;
                ImGui::SetCursorPosX(
                    std::max(0.0f, ImGui::GetContentRegionAvail().x - tw));
                ImGui::PushStyleColor(ImGuiCol_Text,
                    ImVec4(0.25f, 0.75f, 0.95f, 1.0f));
                ImGui::TextWrapped("%s", label.c_str());
                ImGui::PopStyleColor();
            }
            else {
                // Tin nhan tu nguoi khac - can trai
                ImGui::PushStyleColor(ImGuiCol_Text,
                    ImVec4(0.90f, 0.92f, 0.95f, 1.0f));
                ImGui::TextWrapped("[%s]: %s",
                    msg.from.c_str(), msg.text.c_str());
                ImGui::PopStyleColor();
            }
            ImGui::Spacing();
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 10)
            ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::Separator();

    // ── Input box ─────────────────────────────────────────────
    bool sendMsg = false;
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 70);
    if (ImGui::InputText("##input", g_app.inputBuf, sizeof(g_app.inputBuf),
        ImGuiInputTextFlags_EnterReturnsTrue)) {
        sendMsg = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Send", { -1, 0 }) && g_app.chatReady) {
        sendMsg = true;
    }

    if (sendMsg && g_app.chatReady && strlen(g_app.inputBuf) > 0) {
        std::string text(g_app.inputBuf);
        std::string target(g_app.targetUser);
        memset(g_app.inputBuf, 0, sizeof(g_app.inputBuf));

        // GUI không encrypt nữa — chỉ push plaintext
        // network thread sẽ encrypt + send
        pushInputQueue(target, text);
        addMsg("Me", text, true);
    }

    ImGui::Separator();

    // ── Log panel phia duoi ───────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.06f, 0.07f, 0.09f, 1.0f));
    ImGui::BeginChild("##log", { 0, logH }, false);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.50f, 0.55f, 0.60f, 1.0f));
    ImGui::Text("Security Log");
    ImGui::PopStyleColor();
    ImGui::Separator();
    {
        std::lock_guard<std::mutex> lock(g_app.logMutex);
        for (auto& [msg, err] : g_app.logs) {
            ImVec4 col = err ?
                ImVec4(0.90f, 0.40f, 0.40f, 1.0f) :
                ImVec4(0.45f, 0.70f, 0.45f, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, col);
            ImGui::TextWrapped("%s", msg.c_str());
            ImGui::PopStyleColor();
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::End();
}

// ─── Entry point cho render loop ─────────────────────────────
void renderFrame() {
    static bool themeApplied = false;
    if (!themeApplied) { applyTheme(); themeApplied = true; }

    switch (g_app.screen) {
    case AppScreen::LOGIN: renderLoginScreen(); break;
    case AppScreen::MAIN:  renderChatScreen();  break;
    }
}