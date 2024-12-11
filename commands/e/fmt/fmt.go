package fmt

import (
	"fmt"
	"os"
)

// log every print to meow.txt

func logToFile(message string) {
	f, err := os.OpenFile("meow.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(message); err != nil {
		fmt.Println("Error writing to file:", err)
	}
}

func Printf(format string, a ...interface{}) {
	message := fmt.Sprintf(format, a...)
	logToFile(message)
	fmt.Printf(format, a...)
}

func Errorf(format string, a ...interface{}) error {
	message := fmt.Sprintf(format, a...)
	logToFile(message)
	return fmt.Errorf(format, a...)
}

func Println(a ...interface{}) {
	message := fmt.Sprintln(a...)
	logToFile(message)
	fmt.Println(a...)
}
