// +build linux

// Package serverstarter provides a server starter which can be used to do graceful restart.
package serverstarter

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

const (
	stdFdCount          = 3 // stdin, stdout, stderr
	defaultEnvListenFDs = "LISTEN_FDS"
)

// Starter is a server starter.
type Starter struct {
	envListenFDs     string
	workingDirectory string
	listeners        []net.Listener
}

// Option is the type for configuring a Starter.
type Option func(s *Starter)

// New returns a new Starter.
func New(options ...Option) *Starter {
	s := &Starter{
		envListenFDs: defaultEnvListenFDs,
	}
	for _, o := range options {
		o(s)
	}
	return s
}

// SetEnvName sets the environment variable name for passing the listener file descriptor count to the worker process.
// When this options is not called, the environment variable name will be "LISTEN_FDS".
func SetEnvName(name string) Option {
	return func(s *Starter) {
		s.envListenFDs = name
	}
}

// RunMaster starts a worker process and run the loop for starting and stopping the worker
// on signals.
//
// If the master process receives a SIGHUP, it starts a new worker and stop the old worker
// by sending a SIGTERM signal.
// If the master process receives a SIGTERM, it sends the SIGTER to the worker and exists.
func (s *Starter) RunMaster(listeners ...net.Listener) error {
	s.listeners = listeners
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error in RunMaster after failing to get working directory; %v", err)
	}
	s.workingDirectory = wd

	childPid, err := s.startProcess()
	if err != nil {
		return fmt.Errorf("error in RunMaster after starting worker; %v", err)
	}

	sigC := make(chan os.Signal, 1)
	// NOTE: The signals SIGKILL and SIGSTOP may not be caught by a program.
	// https://golang.org/pkg/os/signal/#hdr-Types_of_signals
	signal.Notify(sigC, syscall.SIGHUP, syscall.SIGTERM)
	for {
		sig := <-sigC
		switch sig {
		case syscall.SIGHUP:
			newChildPid, err := s.startProcess()
			if err != nil {
				return fmt.Errorf("error in RunMaster after starting new worker; %v", err)
			}

			err = syscall.Kill(childPid, syscall.SIGTERM)
			if err != nil {
				return fmt.Errorf("error in RunMaster after sending SIGTERM to worker pid=%d after receiving SIGHUP; %v", childPid, err)
			}

			_, err = syscall.Wait4(childPid, nil, 0, nil)
			if err != nil {
				return fmt.Errorf("error in RunMaster after waiting worker pid=%d; %v", childPid, err)
			}

			childPid = newChildPid

		case syscall.SIGTERM:
			err := syscall.Kill(childPid, syscall.SIGTERM)
			if err != nil {
				return fmt.Errorf("error in RunMaster after sending SIGTERM to worker pid=%d after receiving SIGTERM; %v", childPid, err)
			}
			return nil
		}
	}
}

func (s *Starter) startProcess() (pid int, err error) {
	// This code is based on
	// https://github.com/facebookgo/grace/blob/4afe952a37a495ae4ac0c1d4ce5f66e91058d149/gracenet/net.go#L201-L248

	type filer interface {
		File() (*os.File, error)
	}

	files := make([]*os.File, len(s.listeners))
	for i, l := range s.listeners {
		f, err := l.(filer).File()
		if err != nil {
			return 0, fmt.Errorf("error in startProcess after getting file from listener; %v", err)
		}
		files[i] = f
		defer files[i].Close()
	}

	// Use the original binary location. This works with symlinks such that if
	// the file it points to has been changed we will use the updated symlink.
	argv0, err := exec.LookPath(os.Args[0])
	if err != nil {
		return 0, fmt.Errorf("error in startProcess after looking path of the original binary location; %v", err)
	}

	// Pass on the environment and replace the old count key with the new one.
	envListenFDsPrefix := s.envListenFDs + "="
	var env []string
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, envListenFDsPrefix) {
			env = append(env, v)
		}
	}
	envFDs := strconv.AppendInt([]byte(envListenFDsPrefix), int64(len(s.listeners)), 10)
	env = append(env, string(envFDs))

	allFiles := append([]*os.File{os.Stdin, os.Stdout, os.Stderr}, files...)
	process, err := os.StartProcess(argv0, os.Args, &os.ProcAttr{
		Dir:   s.workingDirectory,
		Env:   env,
		Files: allFiles,
	})
	if err != nil {
		return 0, fmt.Errorf("error in startProcess after starting worker process; %v", err)
	}
	return process.Pid, nil
}

// IsMaster returns whether this process is the master or not.
// It returns true if this process is the master, and returns false if this process is the worker.
func (s *Starter) IsMaster() bool {
	_, isWorker := os.LookupEnv(s.envListenFDs)
	return !isWorker
}

// Listeners returns the listeners passed from the master if this is called by the worker process.
// It returns nil when this is called by the master process.
func (s *Starter) Listeners() ([]net.Listener, error) {
	lnCountStr, isWorker := os.LookupEnv(s.envListenFDs)
	if !isWorker {
		return nil, nil
	}

	lnCount, err := strconv.Atoi(lnCountStr)
	if err != nil {
		return nil, fmt.Errorf("error in Listeners after getting invalid listener count; %v", err)
	}
	listeners := make([]net.Listener, lnCount)
	for i := 0; i < lnCount; i++ {
		fd := uintptr(i + stdFdCount)
		file := os.NewFile(fd, "listener")
		l, err := net.FileListener(file)
		if err != nil {
			return nil, fmt.Errorf("error in Listeners after failing to create listener; %v", err)
		}
		listeners[i] = l
	}
	return listeners, nil
}
