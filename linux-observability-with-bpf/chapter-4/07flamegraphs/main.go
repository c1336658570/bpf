package main

import "time"

// sudo go run main.go
// 此程序用来生成CPU负载

func main() {
	j := 3
	for time.Since(time.Now()) < time.Second {
		for i := 1; i < 1000000; i++ {
			j *= i
		}
	}
}
