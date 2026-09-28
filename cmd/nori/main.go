package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nori/internal/auth"
	"nori/internal/config"
	"nori/internal/docker"
	"nori/internal/executor"
	monitorpkg "nori/internal/monitor"
	"nori/internal/notify"
	"nori/internal/poller"
	"nori/internal/registry"
	"nori/internal/scheduler"
	"nori/internal/store"
	terminalsession "nori/internal/terminal"
	"nori/internal/web"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "up" || os.Args[1] == "update" || os.Args[1] == "rollback") {
		if err := runLauncherCommand(context.Background(), os.Args[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		if len(os.Args) < 3 {
			log.Fatal("usage: nori hash-password <password>")
		}
		hash, err := auth.HashPassword(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hash)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	st, err := store.Open(cfg.DBPath, cfg.EncryptionKey)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	if len(os.Args) > 1 && os.Args[1] == "seed-demo" {
		if err := seedDemo(context.Background(), st); err != nil {
			log.Fatalf("seed: %v", err)
		}
		log.Println("seeded demo service")
		return
	}

	dk, err := docker.New(cfg.DockerHost)
	if err != nil {
		log.Fatalf("docker: %v", err)
	}
	if err := initializeSelfService(context.Background(), st, dk); err != nil {
		log.Printf("self-update: %v", err)
	}

	latest := func(ctx context.Context, image string) (string, error) {
		return registry.LatestDigest(image)
	}
	// Build a single notifier instance to share with monitor.
	nf := buildNotifier(cfg, st)
	ex := executor.New(st, executor.OSRunner{}, latest, 0)
	ex.SetDocker(dk)
	ex.SetNotifier(nf)
	ex.SetBotName(st.BotName(context.Background()))
	pl := poller.New(st, latest, ex, cfg.PollInterval)
	sched := scheduler.New(st, ex)

	// Initialize monitor with the same notifier instance as executor
	mon := monitorpkg.New(st, dk, nf, cfg.MonitorInterval)

	a, err := auth.New(cfg.AdminPasswordHash, cfg.SessionKey)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pl.Run(ctx)
	go mon.Run(ctx)
	if err := sched.Start(ctx); err != nil {
		log.Fatalf("scheduler: %v", err)
	}
	defer sched.Stop()

	term := terminalsession.New("nori", cfg.TerminalDir)
	channels := web.Channels{Twilio: cfg.Twilio.Enabled(), Telegram: cfg.Telegram.Enabled()}
	srv := web.NewServer(st, dk, ex, pl, a, channels, term)
	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv}

	go func() {
		log.Printf("listening on %s", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
	_ = httpSrv.Shutdown(context.Background())
}

// buildNotifier returns the notifier chosen by configuration. When no
// channel is configured, the no-op notifier keeps the app behaving exactly
// as before. Every enabled channel is gated by a Route that consults the
// stored per-event routing table at send time, and the channels are fanned
// out through a Multi inside LogFailures so a channel outage can never fail
// a deploy.
func buildNotifier(cfg config.Config, st *store.Store) notify.Notifier {
	approve := func(channel string) func(notify.EventKind) bool {
		return func(kind notify.EventKind) bool {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return notify.EffectiveRouting(st.NotifyRoutingRaw(ctx), st.NotifyMode(ctx)).Allowed(channel, kind)
		}
	}
	var notifiers []notify.Notifier
	if cfg.Twilio.Enabled() {
		notifiers = append(notifiers, &notify.Route{
			Channel: notify.ChannelTwilio,
			Approve: approve(notify.ChannelTwilio),
			Inner: notify.NewTwilio(
				cfg.Twilio.AccountSID,
				cfg.Twilio.AuthToken,
				cfg.Twilio.From,
				cfg.Twilio.To,
			),
		})
	}
	if cfg.Telegram.Enabled() {
		telegram := notify.NewTelegram(
			cfg.Telegram.BotToken,
			cfg.Telegram.ChatID,
		)
		telegram.PublicURL = func(ctx context.Context) string {
			mcp, err := st.GetMCPConfig(ctx)
			if err != nil {
				return ""
			}
			return mcp.PublicURL
		}
		notifiers = append(notifiers, &notify.Route{
			Channel: notify.ChannelTelegram,
			Approve: approve(notify.ChannelTelegram),
			Inner:   telegram,
		})
	}
	if len(notifiers) == 0 {
		return notify.Noop{}
	}
	return &notify.LogFailures{Inner: &notify.Multi{Notifiers: notifiers}}
}
