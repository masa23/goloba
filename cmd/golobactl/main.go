package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/hnakamur/ltsvlog"
	"github.com/masa23/goloba"
	"github.com/masa23/goloba/api"
)

const (
	usage = `Usage argtest [GlobalOptions] <Command> [Options]
Commands:
  info     show information
  weight   change destination weight

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
	case "weight":
		app.weightCommand(args[1:])
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
	format := fs.String("format", "text", "result format, 'text' or 'json'")
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

			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				ltsvlog.Err(ltsvlog.WrapErr(err, func(err error) error {
					return fmt.Errorf("failed to read response from goloba API server")
				}).String("serverURL", s.URL).Stack(""))
			}
			switch *format {
			case "json":
				fmt.Printf("%s:\n%s\n", s.URL, string(data))
			case "text":
				var info api.Info
				err = json.Unmarshal(data, &info)
				if err != nil {
					ltsvlog.Err(ltsvlog.WrapErr(err, func(err error) error {
						return fmt.Errorf("failed to unmarshal JSON response from goloba API server")
					}).String("serverURL", s.URL).Stack(""))
				}
				// ipvsadm output:
				// [root@lbvm01 ~]# ipvsadm -Ln
				// IP Virtual Server version 1.2.1 (size=4096)
				// Prot LocalAddress:Port Scheduler Flags
				//   -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
				// TCP  192.168.122.2:80 wrr
				//   -> 192.168.122.62:80            Route   100    0          0
				//   -> 192.168.122.240:80           Route   500    0          0
				// TCP  192.168.122.2:443 wrr
				//   -> 192.168.122.62:443           Masq    10     0          0
				//   -> 192.168.122.240:443          Masq    20     0          0
				//
				// goloba output:
				// [root@lbvm01 ~]# curl localhost:8880/info
				// Prot LocalAddress:Port Scheduler Flags
				//   -> RemoteAddress:Port           Forward CfgWeight CurWeight Detached Locked ActiveConn InActConn
				// tcp  192.168.122.2:80 wrr
				//   -> 192.168.122.62:80            droute  100       100       true     false  0          0
				//   -> 192.168.122.240:80           droute  500       500       false    false  0          0
				// tcp  192.168.122.2:443 wrr
				//   -> 192.168.122.62:443           masq    10        0         true     false  0          0
				//   -> 192.168.122.240:443          masq    20        20        false    false  0          0
				var buf []byte
				buf = append(append(buf, s.URL...), '\n')
				buf = append(buf, "Prot LocalAddress:Port Scheduler Flags\n"...)
				buf = append(buf, "  -> RemoteAddress:Port           Forward CfgWeight CurWeight ActiveConn InActConn Detached Locked\n"...)
				for _, sr := range info.Services {
					buf = append(buf, fmt.Sprintf("%-4s %s:%d %s\n", sr.Protocol, sr.Address, sr.Port, sr.Schedule)...)
					for _, d := range sr.Destinations {
						hostPort := net.JoinHostPort(d.Address, strconv.Itoa(int(d.Port)))
						buf = append(buf, fmt.Sprintf("  -> %-28s %-7s %-9d %-9d %-8v %-6v %-10d %-9d\n", hostPort, d.Forward, d.ConfigWeight, d.CurrentWeight, d.Detached, d.Locked, d.ActiveConn, d.InactiveConn)...)
					}
				}
				os.Stdout.Write(buf)
			}
		}()
	}
	wg.Wait()
}

func (a *cliApp) weightCommand(args []string) {
	fs := flag.NewFlagSet("weight", flag.ExitOnError)
	fs.Usage = subcommandUsageFunc("weight", fs)
	serviceAddr := fs.String("s", "", "service address in <IPAddress>:<port> form")
	destAddr := fs.String("d", "", "destination address in <IPAddress>:<port> form")
	weight := fs.Uint("w", 100, fmt.Sprintf("destination weight 0-%d", goloba.MaxWeight))
	lock := fs.Bool("lock", false, "lock weight regardless of future healthcheck results")
	fs.Parse(args)

	if goloba.MaxWeight < *weight {
		fs.Usage()
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for _, s := range a.config.APIServers {
		wg.Add(1)
		s := s
		go func() {
			defer wg.Done()

			u := fmt.Sprintf("%s/weight?service=%s&dest=%s&weight=%d&lock=%v",
				s.URL, url.QueryEscape(*serviceAddr), url.QueryEscape(*destAddr), *weight, *lock)
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
