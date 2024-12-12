package fmt

import (
	"fmt"
	"os"
)

func LogToFile(text string) {
	// write to meow.txt

	file, err := os.OpenFile("meow.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	if _, err := file.WriteString(text); err != nil {
		fmt.Println(err)
	}
}

func Printf(format string, a ...interface{}) {
	LogToFile(fmt.Sprintf(format, a...))
	fmt.Printf(format, a...)
}

func Println(a ...interface{}) {
	LogToFile(fmt.Sprintln(a...))
	fmt.Println(a...)
}

func Errorf(format string, a ...interface{}) error {
	LogToFile(fmt.Sprintf(format, a...))
	return fmt.Errorf(format, a...)
}
