package main

import (
	generator "awesomeProject/generator"
	"fmt"
)

func main() {
	generatedPassword, _ := generator.GeneratePass(generator.ULTRA_SECURITY, 8)
	fmt.Println("Here is your generated password:", generatedPassword)
}
