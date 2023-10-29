/*
Simple HTTP file server
(c) Collabora Ltd 2023
Author: Denys Fedoryshchenko <denys.f@collabora.com>
SPDX-License-Identifier: LGPL-2.1-or-later

TODO(nuclearcat): access.log to stdout (configurable)
TODO(nuclearcat): limit file size
TODO(nuclearcat): limit content type (no html, executables, malicious files)
*/
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"

	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	Users   []User `yaml:"users"`
	FileDir string `yaml:"filedir"`
}

type User struct {
	Username string `yaml:"username"`
	Token    string `yaml:"token"`
}

var config Config

var cfg = flag.String("cfg", "", "Configuration file")

// logging
var logEnabled = flag.Bool("log", false, "Enable stdout logging")

/*
Intented to be used as a receiver for the HTTP POST request from the various tools
curl -X POST -H "Authorization: Bearer <token>" -F file0=@var.tar.gz file1=@x.bin http://remotehost/anypath
*/

func loadConfig() {
	var yamlFile []byte

	if *cfg == "" {
		log.Fatal("No config file specified")
	}

	// Load YAML config file
	yamlFile, err := os.ReadFile(*cfg)
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Error parsing YAML file: %v", err)
	}

}

/*
Verify token and return username
If token is not found return empty string
*/
func verifyToken(token string) string {
	for _, user := range config.Users {
		if user.Token == token {
			return user.Username
		}
	}
	return ""
}

/*
Validate filename
*/
func validateFilename(filename string) bool {
	if filename == "" {
		return false
	}
	if filename[0] == '.' {
		return false
	}
	// ascii letters, digits, underscore, dash, dot, tilde, slash
	// TODO(nuclearcat): Write it more elegant
	re := regexp.MustCompile(`^[a-zA-Z0-9_.~/-]+$`)
	if !re.MatchString(filename) {
		return false
	}
	return true
}

/*
Handle file upload
*/
func handleFile(w http.ResponseWriter, r *http.Request, fieldname string, username string) bool {
	var path string = ""
	// Get the file from the request.
	file, fheader, err := r.FormFile(fieldname)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		if *logEnabled {
			log.Println("Error getting file from request:", err)
		}
		return false
	}
	defer file.Close()
	if !validateFilename(fheader.Filename) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid filename"))
		if *logEnabled {
			log.Println("Invalid filename:", fheader.Filename)
		}
		return false
	}

	// if field path exist? (KernelCI uses it)
	if _, ok := r.MultipartForm.Value["path"]; ok {
		path = r.MultipartForm.Value["path"][0]
		if len(path) > 0 && !validateFilename(path) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid path"))
			if *logEnabled {
				log.Println("Invalid path:", path)
			}
			return false
		}
		if len(path) > 0 {
			path += "/"
		}
		if *logEnabled && len(path) > 0 {
			log.Println("Path:", path)
		}
	}

	filename := config.FileDir + "/" + username + "/" + path + fheader.Filename
	// create missing directories for user if needed
	if _, err := os.Stat(config.FileDir + "/" + username + "/" + path); os.IsNotExist(err) {
		os.MkdirAll(config.FileDir+"/"+username+"/"+path, 0755)
	}
	// check if filename contain path, extract directory and create it if needed
	// split filename by slash
	s := regexp.MustCompile(`[\/]`).Split(filename, -1)
	// if there is more than one element, create directory
	if len(s) > 1 {
		os.MkdirAll(s[0], 0755)
	}

	// Create a new file to write the uploaded file to.
	outputFile, err := os.Create(filename)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		if *logEnabled {
			log.Println("Error creating file:", err)
		}
		return false
	}
	defer outputFile.Close()

	// Copy the uploaded file to the new file.
	_, err = io.Copy(outputFile, file)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		if *logEnabled {
			log.Println("Error copying file:", err)
		}
		return false
	}
	return true
}

func doAuth(auth string) string {
	var username string

	// "Bearer " + token, split token from "Bearer " string
	if len(auth) > 7 && auth[:7] == "Bearer " {
		auth = auth[7:]
		username = verifyToken(auth)
		if username == "" {
			if *logEnabled {
				log.Println("NONKciAuth: Token not found")
			}
			return ""
		}
	} else {
		if auth == "" {
			if *logEnabled {
				log.Println("KCIAuth: Token is empty")
			}
			return ""
		}
		// KernelCI token without "Bearer " prefix
		username = verifyToken(auth)
		if username == "" {
			if *logEnabled {
				log.Println("KCIAuth: Token not found")
			}
		}
	}
	if *logEnabled {
		log.Println("Authorized user:", username)
	}

	return username
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	var username string
	// Verify token Authorization header with bearer token and just token
	auth := r.Header.Get("Authorization")
	username = doAuth(auth)
	if username == "" {
		// Return Not Authorized HTTP code
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
		return
	}

	// Parse the request body as a multipart form.
	err := r.ParseMultipartForm(32 << 20)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		if *logEnabled {
			log.Println("Error parsing multipart form:", err)
		}
		return
	}

	/*
		// print all MultiPartForm fields
		if *logEnabled {
			for k, v := range r.MultipartForm.Value {
				log.Println("Field:", k, v)
			}
		}
	*/

	// find all files in the request
	for fieldname, v := range r.MultipartForm.File {
		if *logEnabled {
			log.Println("Uploading file:", fieldname, v[0].Filename, v[0].Size)
		}
		if !handleFile(w, r, fieldname, username) {
			return
		}
	}

	// Write a success message to the response as json
	w.WriteHeader(http.StatusOK)
	// content type json
	w.Header().Set("Content-Type", "application/json")
	json := "{\"status\": \"ok\"}"
	w.Write([]byte(json))
}

func main() {
	port := flag.String("port", "8080", "port number")
	flag.Parse()

	// load config
	loadConfig()

	// Create a handler for upload, any POST, rest just to serve files
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// IP, method, path
		if *logEnabled {
			log.Println(r.RemoteAddr, r.Method, r.URL.Path)
		}
		if r.Method == http.MethodPost {
			handleUpload(w, r)
		} else if r.Method == http.MethodGet {
			http.FileServer(http.Dir(config.FileDir)).ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed"))
		}
	})

	listen_addr := ":" + *port
	log.Println("Listening on", listen_addr)
	log.Fatal(http.ListenAndServe(listen_addr, nil))
}
