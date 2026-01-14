package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ConfigFile = "/etc/zivpn/config.json"
	UserDB     = "/etc/zivpn/users.json"
	SessionDB  = "/etc/zivpn/user_ip_sessions.json"
	DomainFile = "/etc/zivpn/domain"
	ApiKeyFile = "/etc/zivpn/apikey"
	Port       = "/etc/zivpn/api_port"
)

// AuthToken MUST be loaded from /etc/zivpn/apikey at startup.
// Do not hardcode defaults.
var AuthToken string

func loadOrCreateAPIKey(path string) string {
	// Ensure parent dir exists (do not assume installer ran).
	if err := os.MkdirAll("/etc/zivpn", 0755); err != nil {
		log.Fatal("failed to ensure /etc/zivpn exists:", err)
	}

	// If key file doesn't exist, generate a strong random key and write it.
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			b := make([]byte, 32) // 32 bytes => 64 hex chars
			if _, err := rand.Read(b); err != nil {
				log.Fatal("failed to generate api key:", err)
			}
			key := hex.EncodeToString(b)

			// Write with 0600; do not log/print the key.
			if err := os.WriteFile(path, []byte(key+"\n"), 0600); err != nil {
				log.Fatal("failed to write api key file:", err)
			}
		} else {
			log.Fatal("failed to stat api key file:", err)
		}
	}

	// Enforce permissions.
	if err := os.Chmod(path, 0600); err != nil {
		log.Fatal("failed to chmod api key file:", err)
	}
	// Enforce ownership only when running as root.
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 0, 0); err != nil {
			log.Fatal("failed to chown api key file:", err)
		}
	}

	keyBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatal("failed to read api key file:", err)
	}
	key := strings.TrimSpace(string(keyBytes))
	if key == "" {
		log.Fatal("api key file is empty:", path)
	}
	return key
}

type Config struct {
	Listen string `json:"listen"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
	Obfs   string `json:"obfs"`
	Auth   struct {
		Mode   string          `json:"mode"`
		Config json.RawMessage `json:"config"`
	} `json:"auth"`
}

type BotConfig struct {
	BotToken string `json:"bot_token"`
	AdminID  int64  `json:"admin_id"`
}

var notifyMu sync.Mutex
var lastNotify = map[string]int64{}

var ispMu sync.Mutex
var ispCache = map[string]string{}

// lookupISP attempts to resolve ISP/ASN label for an IP. Best-effort: returns "Unknown" on failure.
// Uses ip-api.com by default; you can override via ZIVPN_IPINFO_URL, e.g. "http://ip-api.com/json/%s?fields=status,message,isp".
func lookupISP(ip string) string {
	ispMu.Lock()
	if v, ok := ispCache[ip]; ok {
		ispMu.Unlock()
		return v
	}
	ispMu.Unlock()

	urlT := strings.TrimSpace(os.Getenv("ZIVPN_IPINFO_URL"))
	if urlT == "" {
		urlT = "http://ip-api.com/json/%s?fields=status,message,isp"
	}
	u := fmt.Sprintf(urlT, ip)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	type ipInfoResp struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		ISP     string `json:"isp"`
	}
	var out ipInfoResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "Unknown"
	}
	if strings.ToLower(out.Status) != "success" {
		return "Unknown"
	}
	val := strings.TrimSpace(out.ISP)
	if val == "" {
		val = "Unknown"
	}

	ispMu.Lock()
	ispCache[ip] = val
	ispMu.Unlock()
	return val
}


func loadBotConfig() (*BotConfig, error) {
	b, err := os.ReadFile("/etc/zivpn/bot-config.json")
	if err != nil {
		return nil, err
	}
	var c BotConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.BotToken) == "" || c.AdminID == 0 {
		return nil, fmt.Errorf("invalid bot-config.json (bot_token/admin_id)")
	}
	return &c, nil
}

func getNotifyCooldownSeconds() int64 {
	v := strings.TrimSpace(os.Getenv("ZIVPN_NOTIFY_COOLDOWN_SECONDS"))
	if v == "" {
		return 60
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
		return n
	}
	return 60
}

func notifyAdminMultiLogin(userPw, newIP string, limit int, loginCount int, activeIPs map[string]int64) {
	cfg, err := loadBotConfig()
	if err != nil {
		return
	}

	now := time.Now().Unix()
	cooldown := getNotifyCooldownSeconds()
	key := userPw + "|" + newIP
	notifyMu.Lock()
	if cooldown > 0 {
		if last, ok := lastNotify[key]; ok && (now-last) < cooldown {
			notifyMu.Unlock()
			return
		}
	}
	lastNotify[key] = now
	notifyMu.Unlock()

	// Build notification message
	domain := strings.TrimSpace(os.Getenv("ZIVPN_DOMAIN"))
	if domain == "" {
		domain = "-"
	}
	isp := lookupISP(newIP)

	text := fmt.Sprintf("┌───────────────────┐
   NOTIF MULTI LOGIN 
└───────────────────┘
 Domain   : %s
 Username : %s
 Isp      : %s
 Limit IP : %d
 Login IP : %d
└───────────────────┘", domain, userPw, isp, limit, loginCount)

	form := urlValues(map[string]string{
		"chat_id":    fmt.Sprintf("%d", cfg.AdminID),
		"text":       text,
			})
	_, _ = http.Post("https://api.telegram.org/bot"+cfg.BotToken+"/sendMessage", "application/x-www-form-urlencoded", strings.NewReader(form))
}

func urlValues(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+urlEncode(v))
	}
	return strings.Join(parts, "&")
}

func urlEncode(s string) string {
	r := strings.NewReplacer(
		"%", "%25",
		" ", "%20",
		"\n", "%0A",
		"\r", "%0D",
		"&", "%26",
		"+", "%2B",
		"=", "%3D",
		"?", "%3F",
		"#", "%23",
	)
	return r.Replace(s)
}

type UserRequest struct {
	Password string `json:"password"`
	Days     int    `json:"days"`
	IPLimit  int    `json:"ip_limit"`
}

type UserStore struct {
	Password    string `json:"password"`
	Expired     string `json:"expired"`
	IPLimit     int    `json:"ip_limit,omitempty"`
	LockedUntil int64  `json:"locked_until,omitempty"`

	// Backward compatibility. Not used anymore and will be cleared on save.
	Status string `json:"status,omitempty"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var mutex = &sync.Mutex{}

type UnlockRequest struct {
	Password string `json:"password"`
}

type LockRequest struct {
	Password string `json:"password"`
	Minutes  int    `json:"minutes"` // default 60 if empty/0
}

func lockUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req LockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}
	if req.Password == "" {
		jsonResponse(w, http.StatusBadRequest, false, "Password harus diisi", nil)
		return
	}
	if req.Minutes <= 0 {
		req.Minutes = 60
	}
	if req.Minutes < 1 || req.Minutes > 10080 { // max 7 days
		jsonResponse(w, http.StatusBadRequest, false, "minutes harus 1-10080", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}
	idx, u := findUserByPassword(users, req.Password)
	if u == nil || idx < 0 {
		jsonResponse(w, http.StatusNotFound, false, "User tidak ditemukan", nil)
		return
	}

	users[idx].LockedUntil = time.Now().Unix() + int64(req.Minutes*60)
	if err := saveUsers(users); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil di-lock", map[string]interface{}{
		"locked_until": users[idx].LockedUntil,
		"minutes":      req.Minutes,
	})
}

func unlockUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UnlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}
	if req.Password == "" {
		jsonResponse(w, http.StatusBadRequest, false, "Password harus diisi", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}
	idx, u := findUserByPassword(users, req.Password)
	if u == nil || idx < 0 {
		jsonResponse(w, http.StatusNotFound, false, "User tidak ditemukan", nil)
		return
	}

	users[idx].LockedUntil = 0
	if err := saveUsers(users); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil di-unlock", nil)
}

type SetIPLimitRequest struct {
	Password string `json:"password"`
	IPLimit  int    `json:"ip_limit"`
}

func setIPLimit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req SetIPLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}
	if req.Password == "" {
		jsonResponse(w, http.StatusBadRequest, false, "Password harus diisi", nil)
		return
	}
	if req.IPLimit < 1 || req.IPLimit > 10 {
		jsonResponse(w, http.StatusBadRequest, false, "ip_limit harus 1-10", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}
	idx, u := findUserByPassword(users, req.Password)
	if u == nil || idx < 0 {
		jsonResponse(w, http.StatusNotFound, false, "User tidak ditemukan", nil)
		return
	}

	users[idx].IPLimit = req.IPLimit
	if err := saveUsers(users); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	jsonResponse(w, http.StatusOK, true, "IP limit berhasil diupdate", map[string]interface{}{
		"ip_limit": req.IPLimit,
	})
}

type hysteriaAuthRequest struct {
	Addr    string `json:"addr"`
	Payload string `json:"payload"`
	Send    uint64 `json:"send"`
	Recv    uint64 `json:"recv"`
}

type hysteriaAuthResponse struct {
	OK  bool   `json:"ok"`
	Msg string `json:"msg"`
}

func hysteriaAuthHook(w http.ResponseWriter, r *http.Request) {
	// Hysteria v1 external auth: MUST return HTTP 200 always.
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		_ = json.NewEncoder(w).Encode(hysteriaAuthResponse{OK: false, Msg: "method not allowed"})
		return
	}

	var req hysteriaAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		_ = json.NewEncoder(w).Encode(hysteriaAuthResponse{OK: false, Msg: "bad request"})
		return
	}

	// Parse IP from addr (host:port)
	ip := ""
	if host, _, err := net.SplitHostPort(strings.TrimSpace(req.Addr)); err == nil {
		ip = host
	} else {
		// Fallback: strip port by last ':'
		parts := strings.Split(strings.TrimSpace(req.Addr), ":")
		if len(parts) > 0 {
			ip = parts[0]
		}
	}

	// Decode base64 payload to get AUTH string
	authRaw := strings.TrimSpace(req.Payload)
	if bs, err := base64.StdEncoding.DecodeString(authRaw); err == nil {
		authRaw = strings.TrimSpace(string(bs))
	}

	if ip == "" || authRaw == "" {
		_ = json.NewEncoder(w).Encode(hysteriaAuthResponse{OK: false, Msg: "unauthorized"})
		return
	}

	now := time.Now().Unix()
	today := time.Now().Format("2006-01-02")
	ttl := getSessionTTLSeconds()
	cutoff := now - ttl

	// Load users
	mutex.Lock()
	users, err := loadUsers()
	if err != nil {
		mutex.Unlock()
		_ = json.NewEncoder(w).Encode(hysteriaAuthResponse{OK: false, Msg: "server error"})
		return
	}
	idx, u := findUserByPassword(users, authRaw)
	if u == nil || idx < 0 {
		mutex.Unlock()
		_ = json.NewEncoder(w).Encode(hysteriaAuthResponse{OK: false, Msg: "invalid user"})
		return
	}

	// Expired
	if users[idx].Expired < today {
		mutex.Unlock()
		_ = json.NewEncoder(w).Encode(hysteriaAuthResponse{OK: false, Msg: "expired"})
		return
	}

	// Auto-lock
	if now < users[idx].LockedUntil {
		mutex.Unlock()
		_ = json.NewEncoder(w).Encode(hysteriaAuthResponse{OK: false, Msg: "locked"})
		return
	}

	// Sessions
	sessionsMu.Lock()
	sessions, sErr := loadSessions()
	if sErr != nil {
		sessions = ipSessions{}
	}

	if sessions[authRaw] == nil {
		sessions[authRaw] = map[string]int64{}
	}

	// Cleanup expired IPs for this user
	for sip, last := range sessions[authRaw] {
		if last < cutoff {
			delete(sessions[authRaw], sip)
		}
	}
	// If user map empty, keep (small). Can delete on next cleanup.

	activeCount := len(sessions[authRaw])
	_, already := sessions[authRaw][ip]

	multiLogin := false
	var activeSnapshot map[string]int64
	loginCountNow := 0

	ipLimit := users[idx].IPLimit
	if ipLimit <= 0 {
		ipLimit = 1
	}

	if !already && activeCount >= ipLimit {
		multiLogin = true
		activeSnapshot = make(map[string]int64, len(sessions[authRaw]))
		for k, v := range sessions[authRaw] {
			activeSnapshot[k] = v
		}
		// Do not reject. Allow connection, but notify admin after session is persisted.
	}
// Allowed: update last_seen
	sessions[authRaw][ip] = now

	loginCountNow = len(sessions[authRaw])
	// Also cleanup empty users (optional) and write back
	// Global cleanup to prevent file growth
	for userPw, ips := range sessions {
		for sip, last := range ips {
			if last < cutoff {
				delete(ips, sip)
			}
		}
		if len(ips) == 0 {
			delete(sessions, userPw)
		}
	}
	_ = saveSessions(sessions)

	sessionsMu.Unlock()
	mutex.Unlock()

	if multiLogin {
		go notifyAdminMultiLogin(authRaw, ip, ipLimit, loginCountNow, activeSnapshot)
	}

	_ = json.NewEncoder(w).Encode(hysteriaAuthResponse{OK: true, Msg: "ok"})
}

func startAuthHookServer() {
	addr := strings.TrimSpace(os.Getenv("ZIVPN_AUTH_LISTEN"))
	if addr == "" {
		addr = "127.0.0.1:4488"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", hysteriaAuthHook)

	log.Printf("Auth hook listening at %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("auth hook server error: %v", err)
	}
}
func main() {
	port := flag.Int("port", 8080, "Port to run the API server on")
	flag.Parse()

	// Load (or create) API key and fail fast if invalid.
	AuthToken = loadOrCreateAPIKey(ApiKeyFile)

	// Start local auth hook server for Hysteria external auth.
	go startAuthHookServer()

	http.HandleFunc("/api/user/create", authMiddleware(createUser))
	http.HandleFunc("/api/user/delete", authMiddleware(deleteUser))
	http.HandleFunc("/api/user/renew", authMiddleware(renewUser))
	http.HandleFunc("/api/user/lock", authMiddleware(lockUser))
	http.HandleFunc("/api/user/unlock", authMiddleware(unlockUser))
	http.HandleFunc("/api/user/set_ip_limit", authMiddleware(setIPLimit))
	http.HandleFunc("/api/users", authMiddleware(listUsers))
	http.HandleFunc("/api/info", authMiddleware(getSystemInfo))
	http.HandleFunc("/api/cron/expire", authMiddleware(checkExpiration))
	http.HandleFunc("/api/cron/cleanup", authMiddleware(cleanupExpired))

	log.Printf("Server started at :%d", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-API-Key")
		if token != AuthToken {
			jsonResponse(w, http.StatusUnauthorized, false, "Unauthorized", nil)
			return
		}
		next(w, r)
	}
}

func jsonResponse(w http.ResponseWriter, status int, success bool, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Success: success,
		Message: message,
		Data:    data,
	})
}

func createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	if req.Password == "" || req.Days <= 0 {
		jsonResponse(w, http.StatusBadRequest, false, "Password dan days harus valid", nil)
		return
	}
	if req.IPLimit <= 0 {
		req.IPLimit = 1
	}
	if req.IPLimit < 1 || req.IPLimit > 10 {
		jsonResponse(w, http.StatusBadRequest, false, "ip_limit harus 1-10", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	// Ensure Hysteria uses external auth hook.
	if err := ensureExternalAuthConfigured(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal mengkonfigurasi external auth", nil)
		return
	}

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	if _, u := findUserByPassword(users, req.Password); u != nil {
		jsonResponse(w, http.StatusConflict, false, "User sudah ada", nil)
		return
	}

	expDate := time.Now().AddDate(0, 0, req.Days).Format("2006-01-02")
	newUser := UserStore{
		Password:    req.Password,
		Expired:     expDate,
		IPLimit:     req.IPLimit,
		LockedUntil: 0,
	}
	users = append(users, newUser)

	if err := saveUsers(users); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	domain := "Tidak diatur"
	if domainBytes, err := ioutil.ReadFile(DomainFile); err == nil {
		domain = strings.TrimSpace(string(domainBytes))
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil dibuat", map[string]interface{}{
		"password": req.Password,
		"expired":  expDate,
		"domain":   domain,
		"ip_limit": req.IPLimit,
	})
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	if req.Password == "" {
		jsonResponse(w, http.StatusBadRequest, false, "Password harus diisi", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	idx, u := findUserByPassword(users, req.Password)
	if u == nil || idx < 0 {
		jsonResponse(w, http.StatusNotFound, false, "User tidak ditemukan", nil)
		return
	}

	users = append(users[:idx], users[idx+1:]...)

	if err := saveUsers(users); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	// Cleanup sessions for this user (best effort)
	sessionsMu.Lock()
	if sessions, err := loadSessions(); err == nil {
		delete(sessions, req.Password)
		_ = saveSessions(sessions)
	}
	sessionsMu.Unlock()

	if err := restartService(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal merestart service", nil)
		return
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil dihapus", nil)
}

func renewUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	if req.Password == "" || req.Days <= 0 {
		jsonResponse(w, http.StatusBadRequest, false, "Password dan days harus valid", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	idx, u := findUserByPassword(users, req.Password)
	if u == nil || idx < 0 {
		jsonResponse(w, http.StatusNotFound, false, "User tidak ditemukan", nil)
		return
	}

	users[idx].Expired = time.Now().AddDate(0, 0, req.Days).Format("2006-01-02")

	if err := saveUsers(users); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	if err := restartService(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal merestart service", nil)
		return
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil diperpanjang", map[string]string{
		"password": req.Password,
		"expired":  users[idx].Expired,
	})
}

func listUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	type UserInfo struct {
		Password    string `json:"password"`
		Expired     string `json:"expired"`
		Status      string `json:"status"`
		IPLimit     int    `json:"ip_limit"`
		LockedUntil int64  `json:"locked_until"`
	}

	userList := []UserInfo{}
	today := time.Now().Format("2006-01-02")
	now := time.Now().Unix()

	for _, u := range users {
		status := "Active"
		if now < u.LockedUntil {
			status = "Locked"
		} else if u.Expired < today {
			status = "Expired"
		}

		userList = append(userList, UserInfo{
			Password:    u.Password,
			Expired:     u.Expired,
			Status:      status,
			IPLimit:     u.IPLimit,
			LockedUntil: u.LockedUntil,
		})
	}

	jsonResponse(w, http.StatusOK, true, "Daftar user", userList)
}

func getSystemInfo(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("curl", "-s", "ifconfig.me")
	ipPub, _ := cmd.Output()

	cmd = exec.Command("hostname", "-I")
	ipPriv, _ := cmd.Output()

	domain := "Tidak diatur"
	if domainBytes, err := ioutil.ReadFile(DomainFile); err == nil {
		domain = strings.TrimSpace(string(domainBytes))
	}

	info := map[string]string{
		"domain":     domain,
		"public_ip":  strings.TrimSpace(string(ipPub)),
		"private_ip": strings.Fields(string(ipPriv))[0],
		"port":       "5667",
		"service":    "zivpn",
	}

	jsonResponse(w, http.StatusOK, true, "System Info", info)
}

func checkExpiration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	today := time.Now().Format("2006-01-02")

	revokedCount := 0
	for _, u := range users {
		if u.Expired < today {
			// Expired users will be denied by auth hook; we also clear their runtime sessions.
			log.Printf("User %s expired (Exp: %s). Deny on next auth.\n", maskPassword(u.Password), u.Expired)
			revokeAccess(u.Password)
			revokedCount++
		}
	}

	jsonResponse(w, http.StatusOK, true, fmt.Sprintf("Expiration check complete. Marked expired: %d", revokedCount), nil)
}

// cleanupExpired menghapus semua akun expired dari config.json DAN users.json
func cleanupExpired(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	today := time.Now().Format("2006-01-02")
	activeUsers := []UserStore{}
	deleted := []string{}

	for _, u := range users {
		if u.Expired < today {
			deleted = append(deleted, u.Password)
			continue
		}
		activeUsers = append(activeUsers, u)
	}

	if err := saveUsers(activeUsers); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan users.json", nil)
		return
	}

	// Cleanup sessions for deleted users (best effort)
	sessionsMu.Lock()
	if sessions, err := loadSessions(); err == nil {
		for _, pw := range deleted {
			delete(sessions, pw)
		}
		_ = saveSessions(sessions)
	}
	sessionsMu.Unlock()

	jsonResponse(w, http.StatusOK, true, fmt.Sprintf("Cleanup complete. Deleted: %d", len(deleted)), map[string]interface{}{
		"deleted": len(deleted),
	})
}

func revokeAccess(password string) {
	// With external auth, we cannot revoke a single existing connection from Hysteria.
	// This function now only cleans runtime IP sessions (best effort).
	sessionsMu.Lock()
	if sessions, err := loadSessions(); err == nil {
		delete(sessions, password)
		_ = saveSessions(sessions)
	}
	sessionsMu.Unlock()
}

func enableUser(password string) {
	// Deprecated. With external auth, user enable/disable is handled dynamically.
	_ = password
}

func loadConfig() (Config, error) {
	var config Config
	file, err := ioutil.ReadFile(ConfigFile)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(file, &config)
	return config, err
}

func saveConfig(config Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(ConfigFile, data, 0644)
}

func loadUsers() ([]UserStore, error) {
	var users []UserStore
	file, err := ioutil.ReadFile(UserDB)
	if err != nil {
		if os.IsNotExist(err) {
			return users, nil
		}
		return nil, err
	}
	err = json.Unmarshal(file, &users)
	users = normalizeUsers(users)
	return users, err
}

func saveUsers(users []UserStore) error {
	users = normalizeUsers(users)
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(UserDB, data, 0644)
}

var sessionsMu sync.Mutex

func normalizeUsers(users []UserStore) []UserStore {
	for i := range users {
		if users[i].IPLimit <= 0 {
			users[i].IPLimit = 1
		}
		if users[i].LockedUntil < 0 {
			users[i].LockedUntil = 0
		}
		// Deprecated field
		users[i].Status = ""
	}
	return users
}

func findUserByPassword(users []UserStore, password string) (int, *UserStore) {
	for i := range users {
		if users[i].Password == password {
			return i, &users[i]
		}
	}
	return -1, nil
}

type ipSessions map[string]map[string]int64

func loadSessions() (ipSessions, error) {
	sessions := ipSessions{}
	bs, err := ioutil.ReadFile(SessionDB)
	if err != nil {
		if os.IsNotExist(err) {
			return sessions, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(bs))) == 0 {
		return sessions, nil
	}
	if err := json.Unmarshal(bs, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func saveSessions(sessions ipSessions) error {
	data, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return err
	}
	// Ensure dir exists
	if err := os.MkdirAll("/etc/zivpn", 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(SessionDB, data, 0644)
}

func getSessionTTLSeconds() int64 {
	v := strings.TrimSpace(os.Getenv("ZIVPN_IP_SESSION_TTL_SECONDS"))
	if v == "" {
		return 300
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 300
	}
	return n
}

func maskPassword(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(h[:])[:8]
}

func ensureExternalAuthConfigured() error {
	// Ensure /etc/zivpn/config.json uses external HTTP auth pointing to local auth hook.
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	// default auth hook URL
	authURL := strings.TrimSpace(os.Getenv("ZIVPN_AUTH_HTTP_URL"))
	if authURL == "" {
		authURL = "http://127.0.0.1:4488/auth"
	}

	needsSave := false
	if cfg.Auth.Mode != "external" {
		cfg.Auth.Mode = "external"
		needsSave = true
	}
	// expected config object: {"http":"http://127.0.0.1:4488/auth"}
	expected := map[string]string{"http": authURL}
	expRaw, _ := json.Marshal(expected)

	// If current config isn't same, overwrite.
	if len(cfg.Auth.Config) == 0 || strings.TrimSpace(string(cfg.Auth.Config)) != strings.TrimSpace(string(expRaw)) {
		cfg.Auth.Config = expRaw
		needsSave = true
	}

	if needsSave {
		if err := saveConfig(cfg); err != nil {
			return err
		}
		return restartService()
	}
	return nil
}

func restartService() error {
	cmd := exec.Command("systemctl", "restart", "zivpn.service")
	return cmd.Run()
}
