package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

type Logger struct {
	outMu sync.Mutex
	out   io.Writer // destination for output

	prefix    atomic.Pointer[string] // prefix on each line to identify the logger (but see Lmsgprefix)
	flag      atomic.Int32           // properties
	isDiscard atomic.Bool
}

func (l *Logger) Output(calldepth int, s string) error {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	if l.isDiscard.Load() {
		return nil
	}

	_, err := fmt.Fprintln(l.out, s)
	return err
}

var std = New(os.Stderr, "", 0)

func (l *Logger) SetOutput(w io.Writer) {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	l.out = w
	l.isDiscard.Store(w == io.Discard)
}

func (l *Logger) SetPrefix(prefix string) {
	l.prefix.Store(&prefix)
}

func (l *Logger) SetFlags(flag int) {
	l.flag.Store(int32(flag))
}

func New(out io.Writer, prefix string, flag int) *Logger {
	l := new(Logger)
	l.SetOutput(out)
	l.SetPrefix(prefix)
	l.SetFlags(flag)
	return l
}

func Log(format string, a ...any) {
	fmt.Fprintf(os.Stdout, format, a...)
	fmt.Println()
}

func Fatal(v ...any) {
	std.Output(2, fmt.Sprint(v...))
	os.Exit(1)
}
