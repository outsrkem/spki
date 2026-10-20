package cacert

import "net/http"

// SvcError 业务错误：Svc 决定 HTTP 码 + ecode
type SvcError struct {
	HttpCode int
	Ecode    string
	Msg      string
	Err      error
}

func (e *SvcError) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}
func (e *SvcError) Unwrap() error { return e.Err }

// ---------- 语义化构造器 ----------

// ErrBadRequest 400，ecode 由调用方指定
func ErrBadRequest(ecode, msg string, err error) *SvcError {
	return &SvcError{http.StatusBadRequest, ecode, msg, err}
}

// ErrUnauthorized 401
func ErrUnauthorized(ecode, msg string, err error) *SvcError {
	return &SvcError{http.StatusUnauthorized, ecode, msg, err}
}

// ErrForbidden 403
func ErrForbidden(ecode, msg string, err error) *SvcError {
	return &SvcError{http.StatusForbidden, ecode, msg, err}
}

// ErrNotFound 404
func ErrNotFound(ecode, msg string, err error) *SvcError {
	return &SvcError{http.StatusNotFound, ecode, msg, err}
}

// ErrConflict 409
func ErrConflict(ecode, msg string, err error) *SvcError {
	return &SvcError{http.StatusConflict, ecode, msg, err}
}

// ErrInternal 500
func ErrInternal(ecode, msg string, err error) *SvcError {
	return &SvcError{http.StatusInternalServerError, ecode, msg, err}
}
