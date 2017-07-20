package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"

	"github.com/hnakamur/webapputil/problem"
)

func main() {
	addr := flag.String("addr", ":8080", "server listen address")
	flag.Parse()

	http.HandleFunc("/", handleRoot)
	s := &http.Server{
		Addr: *addr,
	}
	log.Fatal(s.ListenAndServe())
}

func sendResponse(w http.ResponseWriter, statusCode int, detail interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	enc := json.NewEncoder(w)
	return enc.Encode(detail)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Printf("failed to parse form; %v", err)
		return
	}
	p := r.Form.Get("prob")
	switch p {
	case "ex1":
		prob := struct {
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
		}
		err = problem.SendProblem(w, http.StatusForbidden, prob)
		if err != nil {
			log.Printf("failed to send problem; %v", err)
			return
		}
	case "ex2":
		type invalidParam struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		}
		prob := struct {
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
		}
		err = problem.SendProblem(w, http.StatusBadRequest, prob)
		if err != nil {
			log.Printf("failed to send problem; %v", err)
			return
		}
	default:
		err = sendResponse(w, http.StatusOK, struct {
			Msg string `json:"msg"`
		}{
			Msg: "Hello, world!",
		})
		if err != nil {
			log.Printf("failed to send response; %v", err)
			return
		}
	}
}
