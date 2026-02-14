// Package logger provides structured logging with configurable levels and output.
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Level represents the severity of a log message.
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

// String returns the string representation of a log level.
func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a string into a Level.
func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn", "warning":
		return WARN
	case "error":
		return ERROR
	default:
		return INFO
	}
}

// Logger provides structured logging with context fields.
type Logger struct {
	mu        sync.Mutex
	level     Level
	component string
	sessionID string
	writer    io.Writer
	logger    *log.Logger
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// Init initializes the global default logger.
func Init(level string, output string) *Logger {
	once.Do(func() {
		defaultLogger = New(level, output, "main")
	})
	return defaultLogger
}

// Default returns the global default logger, initializing if needed.
func Default() *Logger {
	if defaultLogger == nil {
		return New("info", "stdout", "main")
	}
	return defaultLogger
}

// New creates a new Logger instance.
func New(level string, output string, component string) *Logger {
	l := &Logger{
		level:     ParseLevel(level),
		component: component,
	}

	switch strings.ToLower(output) {
	case "stdout", "":
		l.writer = os.Stdout
	case "stderr":
		l.writer = os.Stderr
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			l.writer = os.Stdout
		} else {
			l.writer = f
		}
	}

	l.logger = log.New(l.writer, "", 0)
	return l
}

// WithComponent returns a new Logger with the given component name.
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		level:     l.level,
		component: component,
		sessionID: l.sessionID,
		writer:    l.writer,
		logger:    log.New(l.writer, "", 0),
	}
}

// WithSession returns a new Logger with the given session ID.
func (l *Logger) WithSession(sessionID string) *Logger {
	return &Logger{
		level:     l.level,
		component: l.component,
		sessionID: sessionID,
		writer:    l.writer,
		logger:    log.New(l.writer, "", 0),
	}
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	msg := fmt.Sprintf(format, args...)

	fields := fmt.Sprintf("[%s] [%-5s] [%s]", timestamp, level, l.component)
	if l.sessionID != "" {
		fields += fmt.Sprintf(" [session:%s]", l.sessionID)
	}

	l.logger.Printf("%s %s", fields, msg)
}

// Debug logs a debug message.
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message.
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a warning message.
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs an error message.
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}
