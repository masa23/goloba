package main

import (
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"

	"github.com/hnakamur/webapputil"
	"github.com/hnakamur/webapputil/problem"
)

func main() {
	addr := flag.String("addr", ":8080", "server listen address")
	flag.Parse()

	http.Handle("/", webapputil.WithErrorHandler(handleRoot, errorHandler))
	s := &http.Server{
		Addr: *addr,
	}
	log.Fatal(s.ListenAndServe())
}

func errorHandler(hErr *webapputil.HTTPError, w http.ResponseWriter, r *http.Request) {
	log.Printf("error in handler; %v", hErr.Error)
	err := problem.SendProblem(w, hErr.Status, hErr.Detail)
	if err != nil {
		log.Printf("failed to send problem; %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) *webapputil.HTTPError {
	err := r.ParseForm()
	if err != nil {
		return webapputil.NewHTTPError(err, http.StatusBadRequest, problem.Problem{
			Type:  "https://example.com/probs/invalid-parameters",
			Title: "Cannot parse form",
		})
	}

	type invalidParam struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}

	p := r.Form.Get("prob")
	switch p {
	case "ex1":
		return webapputil.NewHTTPError(errors.New("example error1"), http.StatusForbidden,
			struct {
				problem.Problem
				Balance  int      `json:"balance"`
				Accounts []string `json:"accounts"`
			}{
				Problem: problem.Problem{
					Type:     "https://example.com/probs/out-of-credit",
					Title:    "You do not have enough credit.",
					Detail:   "Your current balance is 30, but that costs 50.",
					Instance: "/account/12345/msgs/abc",
				},
				Balance: 30,
				Accounts: []string{
					"/account/12345",
					"/account/67890",
				},
			})
	case "ex2":
		return webapputil.NewHTTPError(errors.New("example error2"), http.StatusBadRequest,
			struct {
				problem.Problem
				InvalidParams []invalidParam `json:"invalid-params"`
			}{
				Problem: problem.Problem{
					Type:  "https://example.net/validation-error",
					Title: "Your request parameters didn't validate.",
				},
				InvalidParams: []invalidParam{
					{Name: "age", Reason: "must be a positive integer"},
					{Name: "color", Reason: "must be 'green', 'red' or 'blue'"},
				},
			})
	case "":
		err = sendResponse(w, http.StatusOK, struct {
			Msg string `json:"msg"`
		}{
			Msg: "Hello, world!",
		})
		if err != nil {
			return webapputil.NewHTTPError(err, http.StatusInternalServerError, problem.Problem{
				Type:  "https://example.com/probs/internal-server-error",
				Title: "Failed to send response",
			})
		}
		return nil
	default:
		return webapputil.NewHTTPError(errors.New("example error3"), http.StatusBadRequest,
			struct {
				problem.Problem
				InvalidParams []invalidParam `json:"invalid-params"`
			}{
				Problem: problem.Problem{
					Type:  "https://example.net/validation-error",
					Title: "Your request parameters didn't validate.",
				},
				InvalidParams: []invalidParam{
					{Name: "prob", Reason: "must be a 'ex1', 'ex2' or empty"},
				},
			})
	}
}

func sendResponse(w http.ResponseWriter, statusCode int, detail interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	enc := json.NewEncoder(w)
	return enc.Encode(detail)
}
