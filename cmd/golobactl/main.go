package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/hnakamur/ltsvlog"
)

const (
	usage = `Usage argtest [GlobalOptions] <Command> [Options]
Commands:
  info     show information
  detach   manually detach destination
  attach   manually attach destination

Globals Options:
`
	subcommandOptionsUsageFormat = "\nOptions for subcommand \"%s\":\n"
)

type cliApp struct {
	config     *cliConfig
	httpClient *http.Client
}

type cliConfig struct {
	Timeout    time.Duration     `yaml:"timeout"`
	APIServers []apiServerConfig `yaml:"api_servers"`
}

type apiServerConfig struct {
	URL string `yaml:"url"`
}

func main() {
	config := flag.String("config", "/etc/goloba/golobactl.yml", "config file")
	flag.Usage = func() {
		fmt.Print(usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	conf, err := loadConfig(*config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config file; %v\n", err)
		os.Exit(1)
	}

	app := &cliApp{
		config:     conf,
		httpClient: &http.Client{Timeout: conf.Timeout},
	}
	switch args[0] {
	case "info":
		app.infoCommand(args[1:])
	case "detach":
		app.detachCommand(args[1:])
	case "attach":
		app.attachCommand(args[1:])
	case "unlock":
		app.unlockCommand(args[1:])
	default:
		flag.Usage()
		os.Exit(1)
	}
}

func loadConfig(file string) (*cliConfig, error) {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to read config file, err=%v", err)
		}).String("configFile", file).Stack("")
	}
	var c cliConfig
	err = yaml.Unmarshal(buf, &c)
	if err != nil {
		return nil, ltsvlog.WrapErr(err, func(err error) error {
			return fmt.Errorf("failed to parse config file, err=%v", err)
		}).String("configFile", file).Stack("")
	}
	return &c, nil
}

func subcommandUsageFunc(subcommand string, fs *flag.FlagSet) func() {
	return func() {
		flag.Usage()
		fmt.Printf(subcommandOptionsUsageFormat, subcommand)
		fs.PrintDefaults()
	}
}

func (a *cliApp) infoCommand(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	fs.Usage = subcommandUsageFunc("info", fs)
	fs.Parse(args)

	var wg sync.WaitGroup
	for _, s := range a.config.APIServers {
		wg.Add(1)
		s := s
		go func() {
			defer wg.Done()

			u := fmt.Sprintf("%s/info", s.URL)
			resp, err := a.httpClient.Get(u)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to send request; %v\n", err)
				return
			}
			defer resp.Body.Close()

			fmt.Printf("Response from %s\n", u)
			io.Copy(os.Stdout, resp.Body)
		}()
	}
	wg.Wait()
}

func (a *cliApp) attachCommand(args []string) {
	fs := flag.NewFlagSet("attach", flag.ExitOnError)
	fs.Usage = subcommandUsageFunc("attach", fs)
	serviceAddr := fs.String("s", "", "service address in <IPAddress>:<port> form")
	destAddr := fs.String("d", "", "destination address in <IPAddress>:<port> form")
	lock := fs.Bool("lock", true, "lock attach or detach regardless of future healthcheck results")
	fs.Parse(args)

	var wg sync.WaitGroup
	for _, s := range a.config.APIServers {
		wg.Add(1)
		s := s
		go func() {
			defer wg.Done()

			u := fmt.Sprintf("%s/attach?service=%s&dest=%s&lock=%v",
				s.URL, url.QueryEscape(*serviceAddr), url.QueryEscape(*destAddr), *lock)
			resp, err := a.httpClient.Get(u)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to send request; %v\n", err)
				return
			}
			defer resp.Body.Close()

			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				ltsvlog.Err(ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to read response from goloba API server")
				}).String("serverURL", s.URL).Stack(""))
			}
			fmt.Printf("%s:\n%s\n", s.URL, string(data))
		}()
	}
	wg.Wait()
}

func (a *cliApp) detachCommand(args []string) {
	fs := flag.NewFlagSet("detach", flag.ExitOnError)
	fs.Usage = subcommandUsageFunc("detach", fs)
	serviceAddr := fs.String("s", "", "service address in <IPAddress>:<port> form")
	destAddr := fs.String("d", "", "destination address in <IPAddress>:<port> form")
	lock := fs.Bool("lock", true, "lock detach or detach regardless of future healthcheck results")
	fs.Parse(args)

	var wg sync.WaitGroup
	for _, s := range a.config.APIServers {
		wg.Add(1)
		s := s
		go func() {
			defer wg.Done()

			u := fmt.Sprintf("%s/detach?service=%s&dest=%s&lock=%v",
				s.URL, url.QueryEscape(*serviceAddr), url.QueryEscape(*destAddr), *lock)
			resp, err := a.httpClient.Get(u)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to send request; %v\n", err)
				return
			}
			defer resp.Body.Close()

			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				ltsvlog.Err(ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to read response from goloba API server")
				}).String("serverURL", s.URL).Stack(""))
			}
			fmt.Printf("%s:\n%s\n", s.URL, string(data))
		}()
	}
	wg.Wait()
}

func (a *cliApp) unlockCommand(args []string) {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	fs.Usage = subcommandUsageFunc("unlock", fs)
	serviceAddr := fs.String("s", "", "service address in <IPAddress>:<port> form")
	destAddr := fs.String("d", "", "destination address in <IPAddress>:<port> form")
	fs.Parse(args)

	var wg sync.WaitGroup
	for _, s := range a.config.APIServers {
		wg.Add(1)
		s := s
		go func() {
			defer wg.Done()

			u := fmt.Sprintf("%s/unlock?service=%s&dest=%s",
				s.URL, url.QueryEscape(*serviceAddr), url.QueryEscape(*destAddr))
			resp, err := a.httpClient.Get(u)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to send request; %v\n", err)
				return
			}
			defer resp.Body.Close()

			io.Copy(os.Stdout, resp.Body)
		}()
	}
	wg.Wait()
}
