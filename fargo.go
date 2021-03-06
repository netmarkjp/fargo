package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/k0kubun/pp"
	"github.com/satori/go.uuid"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	config   *Config
	tokens   *Tokens
	failedIP *FailedIP
)

func init() {

	tokenAllowedFrom, _ := ParseNetworks("127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")

	config = &Config{
		FargoAddr:        "0.0.0.0:1236",
		FargoUser:        "fargo",
		FargoPassword:    "fargo",
		StoreDirectory:   "/tmp",
		TokenAllowedFrom: tokenAllowedFrom,
		TokenTTL:         300,
		FileTTL:          600,
	}

	tokens = &Tokens{token: make(map[string]*Token)}
	failedIP = &FailedIP{ip: make(map[string]time.Time)}
}

type Config struct {
	FargoAddr        string
	FargoUser        string
	FargoPassword    string
	StoreDirectory   string
	TokenAllowedFrom []*net.IPNet
	TokenTTL         int64 //sec
	FileTTL          int64 //sec
	sync.Mutex
}

type Token struct {
	ID        string //UUIDv4
	Filename  string
	CreatedAt time.Time
	PushdAt   time.Time
}

type Tokens struct {
	token map[string]*Token //Key: Token.ID, Value: Token
	sync.Mutex
}

type FailedIP struct {
	ip map[string]time.Time
	sync.Mutex
}

func helpHandler(w http.ResponseWriter, r *http.Request) {
	var body []string
	body = append(body, fmt.Sprintf("1. curl --user fargo:fargo http://%s/token", config.FargoAddr))
	body = append(body, fmt.Sprintf("2. curl -F file=@somefile http://%s/push/<TOKEN>", config.FargoAddr))
	body = append(body, fmt.Sprintf("3. curl http://%s/get/<TOKEN>", config.FargoAddr))

	w.WriteHeader(200)
	w.Write([]byte(strings.Join(body, "\n")))
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {

	// maybe TODO, think about X-Forwarded-For
	tcpAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)

	allowed := false
	for _, cidr := range config.TokenAllowedFrom {
		if cidr.Contains(tcpAddr.IP) {
			allowed = true
		}
	}

	if !allowed {
		log.Info("token access not allowed from ", tcpAddr.IP)
		w.WriteHeader(403)
		w.Write([]byte("[ERROR] 403 Forbidden"))
		return
	}

	username, password, ok := r.BasicAuth()
	if !(username == config.FargoUser && password == config.FargoPassword && ok) {
		log.Info("token access not allowed with user \"", username, "\"")
		w.WriteHeader(401)
		w.Write([]byte("[ERROR] 401 Unauthorized"))
		return
	}

	var newToken string
	duplicated := true
	for duplicated {
		newToken = uuid.NewV4().String()
		tokens.Lock()
		if _, exist := tokens.token[newToken]; !exist {
			tokens.token[newToken] = &Token{ID: newToken, CreatedAt: time.Now()}
			duplicated = false
		}
		tokens.Unlock()
	}

	pushURL := fmt.Sprintf("curl -F file=@somefile http://%s/push/%s", config.FargoAddr, newToken)
	w.Write([]byte(pushURL))
}

func pushHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	token := vars["token"]
	log.Debug(token)
	log.Debug(tokens.token)
	if _, exist := tokens.token[token]; !exist {
		log.Warn("token not found.", token)
		w.WriteHeader(404)
		w.Write([]byte("[ERROR] 404 Not Found"))
		return
	}
	if tokens.token[token].CreatedAt.Add(time.Duration(config.TokenTTL) * time.Second).Before(time.Now()) {
		log.Warn("token expired.", token)
		log.Debug("token:", tokens.token[token])
		log.Debug("expired at:", tokens.token[token].CreatedAt.Add(time.Duration(config.TokenTTL)*time.Second))
		w.WriteHeader(403)
		w.Write([]byte("[ERROR] 403 Forbidden"))
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		log.Error(err)
		w.WriteHeader(500)
		w.Write([]byte("[ERROR] 500 Internal Server Error"))
		return
	}
	defer file.Close()

	tmpfile := reflect.ValueOf(header).Elem().FieldByName("tmpfile").String()

	filepath := StoreFilePath(token)
	if tmpfile == "" {
		out, err := os.Create(filepath)
		if err != nil {
			log.Error(err)
			w.WriteHeader(500)
			w.Write([]byte("[ERROR] 500 Internal Server Error"))
			return
		}
		defer out.Close()

		_, err = io.Copy(out, file)
		if err != nil {
			log.Error(err)
			w.WriteHeader(500)
			w.Write([]byte("[ERROR] 500 Internal Server Error"))
			return
		}
	} else {
		err = os.Rename(tmpfile, filepath)
		if err != nil {
			log.Error(err)
			w.WriteHeader(500)
			w.Write([]byte("[ERROR] 500 Internal Server Error"))
			return
		}
	}

	tokens.token[token].Filename = header.Filename
	tokens.token[token].PushdAt = time.Now()

	getURL := fmt.Sprintf("curl -o somefile http://%s/get/%s", config.FargoAddr, token)
	w.WriteHeader(200)
	w.Write([]byte(getURL))
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	tcpaddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	addr := tcpaddr.IP.String()
	if val, exist := failedIP.ip[addr]; exist {
		if val.Add(30 * time.Second).After(time.Now()) {
			log.Warn("access denied for failed IP.")
			w.WriteHeader(403)
			w.Write([]byte("[ERROR] 403 Forbidden"))
			return
		}
	}

	vars := mux.Vars(r)
	token := vars["token"]

	if _, exist := tokens.token[token]; !exist {
		log.Warn("token not found.", token)
		failedIP.Lock()
		failedIP.ip[addr] = time.Now()
		failedIP.Unlock()
		log.Debug("failedIP:", failedIP)
		w.WriteHeader(404)
		w.Write([]byte("[ERROR] 404 Not Found"))
		return
	}
	if tokens.token[token].CreatedAt.Add(time.Duration(config.TokenTTL) * time.Second).Before(time.Now()) {
		log.Warn("token expired.", token)
		failedIP.Lock()
		failedIP.ip[addr] = time.Now()
		failedIP.Unlock()
		w.WriteHeader(403)
		w.Write([]byte("[ERROR] 403 Forbidden"))
		return
	}

	failedIP.Lock()
	delete(failedIP.ip, addr)
	failedIP.Unlock()

	filepath := StoreFilePath(token)

	contentDescription := fmt.Sprintf("attachment; filename=\"%s\"", tokens.token[token].Filename)
	w.Header().Add("Content-Disposition", contentDescription)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filepath)

}

func fileGC() {
	for {
		for k := range tokens.token {
			if tokens.token[k].PushdAt.After(tokens.token[k].CreatedAt) &&
				tokens.token[k].PushdAt.Add(time.Duration(config.FileTTL)*time.Second).Before(time.Now()) {
				log.Debug("file gc: clean up ", k)
				filepath := StoreFilePath(k)
				if err := os.Remove(filepath); err != nil {
					log.Error("failed to remove file. ", err)
				}
				tokens.Lock()
				delete(tokens.token, k)
				tokens.Unlock()
			}
		}
		time.Sleep(10 * time.Second)
	}
}

func StoreFilePath(token string) string {
	filepath := fmt.Sprintf("%s%c%s",
		config.StoreDirectory,
		os.PathSeparator,
		token)
	return filepath
}

func ParseNetworks(description string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, cidr := range strings.Split(description, ",") {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func main() {
	var err error
	log.SetOutput(os.Stderr)
	log.SetLevel(log.InfoLevel)

	var debug bool
	flag.BoolVar(&debug, "d", false, "debug logging (default: false)")

	flag.Parse()

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	config.Lock()
	if envFargoAddr := os.Getenv("FARGO_ADDR"); envFargoAddr != "" {
		config.FargoAddr = envFargoAddr
	}
	if envFargoUser := os.Getenv("FARGO_USER"); envFargoUser != "" {
		config.FargoUser = envFargoUser
	}
	if envFargoPassword := os.Getenv("FARGO_PASSWORD"); envFargoPassword != "" {
		config.FargoPassword = envFargoPassword
	}
	if envTokenAllowedFrom := os.Getenv("TOKEN_ALLOWED_FROM"); envTokenAllowedFrom != "" {
		networks, err := ParseNetworks(envTokenAllowedFrom)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		config.TokenAllowedFrom = networks
	}
	if envFileTTL, err := strconv.ParseInt(os.Getenv("FILE_TTL"), 10, 64); err == nil && envFileTTL != 0 {
		config.FileTTL = envFileTTL
	}
	if envStoreDirectory := os.Getenv("STORE_DIR"); envStoreDirectory != "" {
		if _, err := os.Stat(envStoreDirectory); err != nil {
			err := os.Mkdir(envStoreDirectory, 0777)
			if err != nil {
				log.Fatal("cannot create ", envStoreDirectory, " : ", err)
				os.Exit(1)
			}
		}

		config.StoreDirectory = envStoreDirectory
	}
	if envTokenTTL, err := strconv.ParseInt(os.Getenv("TOKEN_TTL"), 10, 64); err == nil && envTokenTTL != 0 {
		config.TokenTTL = envTokenTTL
	}
	config.Unlock()

	log.Debug("config: ", pp.Sprint(config))

	r := mux.NewRouter()
	r.HandleFunc("/token/", tokenHandler).Methods("GET")
	r.HandleFunc("/token", tokenHandler).Methods("GET")
	r.HandleFunc("/push/{token}", pushHandler).Methods("POST")
	r.HandleFunc("/get/{token}", getHandler).Methods("GET")
	r.HandleFunc("/help/", helpHandler).Methods("GET")
	r.HandleFunc("/help", helpHandler).Methods("GET")
	r.HandleFunc("/", helpHandler).Methods("GET")
	http.Handle("/", r)

	go fileGC()

	log.Debug("http server started")

	err = http.ListenAndServe(config.FargoAddr, nil)
	if err != nil {
		log.Error(err)
	}
}
