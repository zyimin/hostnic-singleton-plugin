package main

import (
	"os"
	"os/user"
	"strconv"

	"./driver"
	"./log"

	"github.com/docker/go-plugins-helpers/network"
	"github.com/urfave/cli"
)

const (
	version = "0.1"
)

func main() {
	var flagDebug = cli.BoolFlag{
		Name:  "debug, d",
		Usage: "enable debugging",
	}
	app := cli.NewApp()
	app.Name = "hostnic"
	app.Usage = "Docker Host Nic Network Plugin"
	app.Version = version
	app.Flags = []cli.Flag{
		flagDebug,
	}
	app.Action = Run
	app.Run(os.Args)
}

// Run initializes the driver
func Run(ctx *cli.Context) {
	if ctx.Bool("debug") {
		log.SetLevel("debug")
	}
	log.Info("Run %s", ctx.App.Name)
	d, err := driver.New()
	if err == nil {
		u, _ := user.Lookup("root")
		gid, _ := strconv.Atoi(u.Gid)
		h := network.NewHandler(d)
		err = h.ServeUnix("/run/docker/plugins/hostnic.sock", gid)
	}
	if err != nil {
		log.Fatal("Run app error: %s", err.Error())
		os.Exit(1)
	}
}
