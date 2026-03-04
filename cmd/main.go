package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/unicitynetwork/bft-go-base/util"
	"gopkg.in/yaml.v3"

	"github.com/unicitynetwork/finality-gadget/logger"
)

const (
	envPrefix               = "FGP"
	defaultConfigFile       = "config.props"
	defaultDir              = ".fgp"
	defaultLoggerConfigFile = "logger-config.yaml"

	keyHome   = "home"
	keyConfig = "config"

	flagNameLoggerCfgFile = "logger-config"
	flagNameLogOutputFile = "log-file"
	flagNameLogLevel      = "log-level"
	flagNameLogFormat     = "log-format"

	shardConfDBFileName = "shard.db"
	blockDBFileName     = "blocks.db"
)

var errQuitSignal = errors.New("received quit signal")

func main() {
	ctx := quitSignalContext()

	flags := &cliFlags{}
	var rootCmd = &cobra.Command{
		Use:           "fgp",
		Short:         "Finality Gadget CLI",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := initializeConfig(cmd, flags); err != nil {
				return fmt.Errorf("failed to initialize configuration: %w", err)
			}
			return nil
		},
	}

	// Base Flags
	rootCmd.PersistentFlags().StringVar(&flags.HomeDir, keyHome, "", fmt.Sprintf("set the FGP_HOME for this invocation (default is %s)", defaultHomeDir()))
	rootCmd.PersistentFlags().StringVar(&flags.CfgFile, keyConfig, "", fmt.Sprintf("config file URL (default is $FGP_HOME/%s)", defaultConfigFile))
	rootCmd.PersistentFlags().StringVar(&flags.LogCfgFile, flagNameLoggerCfgFile, defaultLoggerConfigFile, "logger config file URL. Considered absolute if starts with '/'. Otherwise relative from $FGP_HOME.")
	rootCmd.PersistentFlags().String(flagNameLogOutputFile, "", "log file path or one of the special values: stdout, stderr, discard")
	rootCmd.PersistentFlags().String(flagNameLogLevel, "", "logging level, one of: DEBUG, INFO, WARN, ERROR")
	rootCmd.PersistentFlags().String(flagNameLogFormat, "", "log format, one of: text, json, console, ecs")

	rootCmd.AddCommand(newRunCmd(flags))
	rootCmd.AddCommand(newBlockCmd(flags))

	if err := rootCmd.ExecuteContext(ctx); err != nil && !cancelledByQuitSignal(ctx) {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func initializeConfig(cmd *cobra.Command, flags *cliFlags) error {
	v := viper.New()

	if flags.HomeDir == "" {
		flags.HomeDir = os.Getenv(strings.ToUpper(envPrefix + "_" + keyHome))
		if flags.HomeDir == "" {
			flags.HomeDir = defaultHomeDir()
		}
	}

	if flags.CfgFile == "" {
		flags.CfgFile = os.Getenv(strings.ToUpper(envPrefix + "_" + keyConfig))
		if flags.CfgFile == "" {
			flags.CfgFile = defaultConfigFile
		}
	}
	if !filepath.IsAbs(flags.CfgFile) {
		flags.CfgFile = filepath.Join(flags.HomeDir, flags.CfgFile)
	}

	if _, err := os.Stat(flags.CfgFile); err == nil {
		v.SetConfigFile(flags.CfgFile)
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}

	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()

	var bindFlagErr []error
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name == keyHome || f.Name == keyConfig {
			return
		}
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			if err := v.BindEnv(f.Name, fmt.Sprintf("%s_%s", envPrefix, envVarSuffix)); err != nil {
				bindFlagErr = append(bindFlagErr, fmt.Errorf("binding env to flag %q: %w", f.Name, err))
				return
			}
		}
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
				bindFlagErr = append(bindFlagErr, fmt.Errorf("setting flag %q value: %w", f.Name, err))
				return
			}
		}
	})

	return errors.Join(bindFlagErr...)
}

func initLogger(flags *cliFlags, cmd *cobra.Command) (*slog.Logger, error) {
	cfg := &logger.LogConfiguration{}

	loggerCfgFile := flags.LogCfgFile
	if !filepath.IsAbs(loggerCfgFile) {
		loggerCfgFile = filepath.Join(flags.HomeDir, loggerCfgFile)
	}
	loggerCfgFile = filepath.Clean(loggerCfgFile)

	if f, err := os.Open(loggerCfgFile); err != nil {
		defaultLoggerCfg := filepath.Join(flags.HomeDir, defaultLoggerConfigFile)
		if loggerCfgFile != defaultLoggerCfg && !util.FileExists(loggerCfgFile) {
			return nil, fmt.Errorf("opening logger configuration file: %w", err)
		}
	} else {
		defer f.Close()
		if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
			return nil, fmt.Errorf("decoding logger configuration (%s): %w", loggerCfgFile, err)
		}
	}

	getFlagValueIfSet := func(flagName string, value *string) error {
		if cmd.Flags().Changed(flagName) {
			var err error
			if *value, err = cmd.Flags().GetString(flagName); err != nil {
				return fmt.Errorf("failed to read %s flag value: %w", flagName, err)
			}
		}
		return nil
	}

	if err := getFlagValueIfSet(flagNameLogLevel, &cfg.Level); err != nil {
		return nil, err
	}
	if err := getFlagValueIfSet(flagNameLogFormat, &cfg.Format); err != nil {
		return nil, err
	}
	if err := getFlagValueIfSet(flagNameLogOutputFile, &cfg.OutputPath); err != nil {
		return nil, err
	}

	return logger.New(cfg)
}

func loadConf[T any](path string, conf *T) error {
	if _, err := util.ReadJsonFile(path, conf); err != nil {
		return fmt.Errorf("failed to load %q: %w", path, err)
	}
	return nil
}

func defaultHomeDir() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		panic("default user home dir not defined: " + err.Error())
	}
	return filepath.Join(dir, defaultDir)
}

func quitSignalContext() context.Context {
	ctx, cancel := context.WithCancelCause(context.Background())
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sigChan)
		sig := <-sigChan
		cancel(fmt.Errorf("%s: %w", sig, errQuitSignal))
	}()
	return ctx
}

func cancelledByQuitSignal(ctx context.Context) bool {
	err := context.Cause(ctx)
	return err != nil && errors.Is(err, errQuitSignal)
}
