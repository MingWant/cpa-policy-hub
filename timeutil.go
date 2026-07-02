package main

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

func dayKey(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

func hourKey(t time.Time) string {
	return t.UTC().Format("2006-01-02T15Z")
}

func monthKey(t time.Time) string {
	return t.UTC().Format("2006-01")
}

func policyRequestDayKey(t time.Time) string {
	return "requests:" + dayKey(t)
}

func policyRequestMonthKey(t time.Time) string {
	return "requests:" + monthKey(t)
}

func minuteKey(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04Z")
}

func randomHex(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, errRead := rand.Read(buf); errRead != nil {
		return "", errRead
	}
	return hex.EncodeToString(buf), nil
}
