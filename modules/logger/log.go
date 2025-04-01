package logger

import (
	"fmt"
)

var (
	ColorReset     = "\033[0m"
	ColorBlack     = "\033[30m"
	ColorRed       = "\033[31m"
	ColorGreen     = "\033[32m"
	ColorYellow    = "\033[33m"
	ColorOrange    = "\033[38;5;202m"
	ColorBlue      = "\033[34m"
	ColorMagenta   = "\033[35m"
	ColorCyan      = "\033[36m"
	ColorGray      = "\033[37m"
	ColorDarkGray  = "\033[90m"
	ColorWhite     = "\033[97m"
	ColorBold      = "\033[1m"
	ColorItalic    = "\033[3m"
	ColorUnderline = "\033[4m"
	ColorInvert    = "\033[7m"

	TelekomMagenta = "\033[38;2;226;0;116m"
	NeatRed        = "\033[38;5;197m"
	Blurple        = "\033[38;2;114;137;218m"

	ColorBrightRed     = "\033[91m"
	ColorBrightGreen   = "\033[92m"
	ColorBrightYellow  = "\033[93m"
	ColorBrightBlue    = "\033[94m"
	ColorBrightMagenta = "\033[95m"
	ColorBrightCyan    = "\033[96m"
	ColorBrightWhite   = "\033[97m"

	LogPrefix   = fmt.Sprintf("%s[%sLOG%s] %s", ColorDarkGray, Blurple, ColorDarkGray, ColorReset)
	PanicPrefix = fmt.Sprintf("%s[%sPANIC%s] %s", ColorDarkGray, NeatRed, ColorDarkGray, ColorReset)

	b1 = " _      _________  _______    _  _____________      ______  ___  __ __"
	b2 = "| | /| / /  _/ _ \\/ __/ _ \\  / |/ / __/_  __/ | /| / / __ \\/ _ \\/ //_/"
	b3 = "| |/ |/ // // , _/ _// // / /    / _/  / /  | |/ |/ / /_/ / , _/ ,<"
	b4 = "|__/|__/___/_/|_/___/____/ /_/|_/___/ /_/   |__/|__/\\____/_/|_/_/|_|"

	bannerGradient = ColorGradient("#5965F0", "#8DA3F2", 4)
	Banner         = fmt.Sprintf("%s%s\n%s%s\n%s%s\n%s%s\n%s\n", bannerGradient[0], b1, bannerGradient[1], b2, bannerGradient[2], b3, bannerGradient[3], b4, ColorReset)
)

func Color(input interface{}, color ...string) string {
	var s string
	c := ""
	for i := range color {
		c = c + color[i]
	}

	s = c + fmt.Sprint(input) + ColorReset
	return s
}

func Print(a ...any) {
	fmt.Print(a...)
}

func Printf(format string, a ...any) {
	fmt.Printf(format, a...)
}

func Println(a ...any) {
	fmt.Println(LogPrefix + fmt.Sprint(a...))
}

func Sprintf(format string, a ...any) string {
	return fmt.Sprintf(format, a...)
}

func Fatal(generalMsg string, a ...any) {
	fmt.Print("\n\n")
	fmt.Println(PanicPrefix + generalMsg)
	fmt.Printf("%s==============================================%s\n", ColorDarkGray, ColorReset)
	fmt.Println(a...)
	fmt.Printf("%s==============================================%s\n", ColorDarkGray, ColorReset)
	panic(a)
}

func Fatalf(format string, a ...any) {
	fmt.Printf(format, a...)
	panic(fmt.Sprintf(format, a...))
}

func ColorGradient(rgb1, rgb2 string, steps int) []string {
	var gradient []string

	var r1, g1, b1, r2, g2, b2 int
	fmt.Sscanf(rgb1, "#%02x%02x%02x", &r1, &g1, &b1)
	fmt.Sscanf(rgb2, "#%02x%02x%02x", &r2, &g2, &b2)

	deltaR := float64(r2-r1) / float64(steps-1)
	deltaG := float64(g2-g1) / float64(steps-1)
	deltaB := float64(b2-b1) / float64(steps-1)

	for i := 0; i < steps; i++ {
		r := int(float64(r1) + deltaR*float64(i))
		g := int(float64(g1) + deltaG*float64(i))
		b := int(float64(b1) + deltaB*float64(i))

		gradient = append(gradient, fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b))
	}

	return gradient
}
