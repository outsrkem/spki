package slog

import (
	"strings"

	"github.com/cloudwego/hertz/pkg/common/hlog"
	hertzslog "github.com/hertz-contrib/logger/slog"
)

// logLevel determines the log level based on a provided string.
// Parameters:
//   - lev: A string representing the log level.
//
// Returns:
//   - The hlog.Level value corresponding to the provided log level string.
func logLevel(lev string) hlog.Level {
	lowerLev := strings.ToLower(lev)
	switch lowerLev {
	case "debug":
		return hlog.LevelDebug
	case "info":
		return hlog.LevelInfo
	case "warn":
		return hlog.LevelWarn
	case "error":
		return hlog.LevelError
	case "fatal":
		return hlog.LevelFatal
	default:
		return hlog.LevelInfo
	}
}

func InitLog(lev string) {
	logger := hertzslog.NewLogger()
	logger.SetLevel(logLevel(lev))
	hlog.SetLogger(logger)
}
