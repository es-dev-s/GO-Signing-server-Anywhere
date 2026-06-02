// One-off: go run ./scripts/smoke_ws.go (loads signing-server-go/.env)
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load(".env")
	host := os.Getenv("HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "18085"
	}
	token := strings.Trim(os.Getenv("WS_CONNECT_TOKEN"), `"`)
	if token == "" {
		log.Fatal("WS_CONNECT_TOKEN missing in .env")
	}
	u := url.URL{Scheme: "ws", Host: fmt.Sprintf("%s:%s", host, port), RawQuery: "token=" + url.QueryEscape(token)}
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, raw, err := c.ReadMessage()
	if err != nil {
		log.Fatalf("read welcome: %v", err)
	}
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		log.Fatalf("json: %v", err)
	}
	if msg["type"] != "welcome" || msg["socketId"] == nil {
		log.Fatalf("unexpected welcome: %s", string(raw))
	}
	ice, _ := msg["iceServers"].([]any)
	fmt.Printf("OK welcome socketId=%v iceServers=%d\n", msg["socketId"], len(ice))
}
