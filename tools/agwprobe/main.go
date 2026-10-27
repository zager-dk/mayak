// Проверка совместимости: настоящий клиент шлюза libagw против сервера Маяка.
// Использование: agwprobe <endpoint> <public.pem> <path> <payload-json>
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/amnezia-vpn/libagw/gateway"
)

func main() {
	pem, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	c := gateway.New(gateway.Config{GatewayEndpoint: os.Args[1], PublicKeyPEM: pem, RequestTimeout: 5 * time.Second})
	resp, err := c.Post(context.Background(), os.Args[3], []byte(os.Args[4]), gateway.PostOptions{ServiceType: "mayak", UserCountryCode: "ru"})
	if err != nil {
		fmt.Println("ERR", err)
		for _, l := range resp.Trace {
			fmt.Println("  ", l)
		}
		os.Exit(1)
	}
	fmt.Println("OK", string(resp.Body))
}
