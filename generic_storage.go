/*
Simple HTTP file server
(c) Collabora Ltd 2023
Author: Denys Fedoryshchenko <denys.f@collabora.com>

TODO(nuclearcat): access.log to stdout (configurable)
TODO(nuclearcat): limit file size
TODO(nuclearcat): limit content type (no html, executables, malicious files)

*/
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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

/*
Intented to be used as a receiver for the HTTP POST request from the various tools
curl -X POST -H "Authorization: Bearer <token>" -F file0=@var.tar.gz file1=@x.bin http://remotehost/anypath
*/

func loadConfig() {
	var yamlFile []byte
	// Load YAML config file
	yamlFile, err := ioutil.ReadFile(*cfg)
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
	// Get the file from the request.
	file, fheader, err := r.FormFile(fieldname)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return false
	}
	defer file.Close()
	if !validateFilename(fheader.Filename) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid filename"))
		return false
	}

	filename := config.FileDir + "/" + username + "/" + fheader.Filename
	// create missing directories for user if needed
	if _, err := os.Stat(config.FileDir + "/" + username); os.IsNotExist(err) {
		os.MkdirAll(config.FileDir+"/"+username, 0755)
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
		return false
	}
	defer outputFile.Close()

	// Copy the uploaded file to the new file.
	_, err = io.Copy(outputFile, file)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return false
	}
	return true
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	var username string
	// Verify token Authorization header with bearer token and just token
	auth := r.Header.Get("Authorization")
	// "Bearer " + token, split token from "Bearer " string
	if len(auth) > 7 {
		auth = auth[7:]
		username = verifyToken(auth)
		if username == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
		return
	}

	// Parse the request body as a multipart form.
	err := r.ParseMultipartForm(32 << 20)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	// iterate over fields file0, file1, file2, etc
	for i := 0; i < 100; i++ {
		fieldname := fmt.Sprintf("file%d", i)
		// if field is not found, break
		if r.MultipartForm.File[fieldname] == nil {
			break
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
