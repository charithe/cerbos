// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package kafka_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/kafka"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	redpandaImage   = "redpandadata/redpanda"
	redpandaVersion = "v23.2.15"

	defaultIntegrationTopic = "cerbos"
	maxWait                 = 60 * time.Second
)

func TestProduceWithTLS(t *testing.T) {
	// Redpanda tries to create a temporary configuration file in /etc/redpanda (or whichever directory specified by --config)
	// When that directory is a docker mount, the temp file creation fails because the Redpanda process is running as a user who
	// doesn't have enough privileges to do so.
	t.Skip("TLS cannot be tested on Docker due to https://github.com/redpanda-data/redpanda/issues/12717")
	t.Parallel()

	ctx := context.Background()

	// setup kafka
	uri := newKafkaBrokerWithTLS(t, defaultIntegrationTopic, "testdata/valid/rpk/ca.crt", "testdata/valid/client/tls.crt", "testdata/valid/client/tls.key")
	log, err := newLog(map[string]any{
		"audit": map[string]any{
			"enabled": true,
			"backend": "kafka",
			"kafka": map[string]any{
				"authentication": map[string]any{
					"tls": map[string]any{
						"caPath":         "testdata/valid/rpk/ca.crt",
						"certPath":       "testdata/valid/client/tls.crt",
						"keyPath":        "testdata/valid/client/tls.key",
						"reloadInterval": "10s",
					},
				},
				"brokers":     []string{uri},
				"topic":       defaultIntegrationTopic,
				"produceSync": true,
			},
		},
	})
	require.NoError(t, err)

	// write audit log entries
	err = log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
		return &auditv1.AccessLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA1",
		}, nil
	})
	require.NoError(t, err)

	err = log.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		return &auditv1.DecisionLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA2",
		}, nil
	})
	require.NoError(t, err)

	// validate we see this entries in kafka
	records, err := fetchKafkaTopic(t, uri, defaultIntegrationTopic, true)
	require.NoError(t, err)
	require.Len(t, records, 2, "unexpected number of published audit log entries")
}

func TestSyncProduce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// setup kafka
	uri := newKafkaBroker(t, defaultIntegrationTopic)
	log, err := newLog(map[string]any{
		"audit": map[string]any{
			"enabled": true,
			"backend": "kafka",
			"kafka": map[string]any{
				"brokers":     []string{uri},
				"topic":       defaultIntegrationTopic,
				"produceSync": true,
			},
		},
	})
	require.NoError(t, err)

	// write audit log entries
	err = log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
		return &auditv1.AccessLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA1",
		}, nil
	})
	require.NoError(t, err)

	err = log.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		return &auditv1.DecisionLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA2",
		}, nil
	})
	require.NoError(t, err)

	// validate we see this entries in kafka
	records, err := fetchKafkaTopic(t, uri, defaultIntegrationTopic, false)
	require.NoError(t, err)
	require.Len(t, records, 2, "unexpected number of published audit log entries")
}

func TestCompression(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// setup kafka
	uri := newKafkaBroker(t, defaultIntegrationTopic)

	for _, compression := range []string{"none", "gzip", "snappy", "lz4", "zstd"} {
		log, err := newLog(map[string]any{
			"audit": map[string]any{
				"enabled": true,
				"backend": "kafka",
				"kafka": map[string]any{
					"brokers":     []string{uri},
					"topic":       defaultIntegrationTopic,
					"produceSync": true,
					"compression": []string{compression},
				},
			},
		})
		require.NoError(t, err)

		// write audit log entries
		callId, err := audit.NewID()
		require.NoError(t, err)

		err = log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
			return &auditv1.AccessLogEntry{
				CallId: string(callId),
			}, nil
		})
		require.NoError(t, err)
	}

	// validate we see these entries in kafka
	records, err := fetchKafkaTopic(t, uri, defaultIntegrationTopic, false)
	require.NoError(t, err)
	require.Len(t, records, 5, "unexpected number of published audit log entries")
}

func TestAsyncProduce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// setup kafka
	uri := newKafkaBroker(t, defaultIntegrationTopic)
	log, err := newLog(map[string]any{
		"audit": map[string]any{
			"enabled": true,
			"backend": "kafka",
			"kafka": map[string]any{
				"brokers":     []string{uri},
				"topic":       defaultIntegrationTopic,
				"produceSync": false,
			},
		},
	})
	require.NoError(t, err)

	// write audit log entries
	err = log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
		return &auditv1.AccessLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA1",
		}, nil
	})
	require.NoError(t, err)

	err = log.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		return &auditv1.DecisionLogEntry{
			CallId: "01ARZ3NDEKTSV4RRFFQ69G5FA2",
		}, nil
	})
	require.NoError(t, err)

	// validate we see this entries in kafka, eventually
	require.Eventually(t, func() bool {
		records, err := fetchKafkaTopic(t, uri, defaultIntegrationTopic, false)
		require.NoError(t, err)
		return len(records) == 2
	}, 10*time.Second, 100*time.Millisecond, "expected to see audit log entries in kafka")
}

func newKafkaBrokerWithTLS(t *testing.T, topic, caPath, certPath, keyPath string) string {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	duration := 10 * time.Second
	skipVerify := false
	tlsConfig, err := kafka.NewTLSConfig(ctx, duration, skipVerify, caPath, certPath, keyPath)
	require.NoError(t, err)

	return startKafkaBroker(t, topic, tlsConfig)
}

func newKafkaBroker(t *testing.T, topic string) string {
	t.Helper()

	return startKafkaBroker(t, topic, nil)
}

func startKafkaBroker(t *testing.T, topic string, tlsConfig *tls.Config) string {
	t.Helper()

	hostPort, err := util.GetFreeListenAddr()
	require.NoError(t, err, "Failed to find free address")

	host, port, err := net.SplitHostPort(hostPort)
	require.NoError(t, err, "Failed to split free address: %s", hostPort)

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "Failed to connect to Docker")
	pool.MaxWait = maxWait

	runOpts := &dockertest.RunOptions{
		Repository: redpandaImage,
		Tag:        redpandaVersion,
		Cmd: []string{
			"redpanda",
			"start",
			"--mode", "dev-container",
			// kafka admin client will retrieve the advertised address from the broker
			// so we need it to use the same port that is exposed on the container
			"--advertise-kafka-addr", hostPort,
		},
		ExposedPorts: []string{
			"9092/tcp",
		},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9092/tcp": {{HostIP: host, HostPort: port}},
		},
	}

	var clientOpts []kgo.Opt
	exposedPort := "9092/tcp"
	if tlsConfig != nil {
		testDataAbsPath, err := filepath.Abs("testdata/valid")
		require.NoError(t, err)

		exposedPort = "65136/tcp"
		runOpts.ExposedPorts = append(runOpts.ExposedPorts, exposedPort)
		runOpts.PortBindings[docker.Port(exposedPort)] = []docker.PortBinding{{HostIP: host, HostPort: port}}
		delete(runOpts.PortBindings, docker.Port(exposedPort))

		runOpts.Mounts = []string{
			fmt.Sprintf("%s:/var/lib/redpanda/.config/rpk", filepath.Join(testDataAbsPath, "rpk")),
			fmt.Sprintf("%s:/etc/redpanda", filepath.Join(testDataAbsPath, "redpanda")),
		}

		clientOpts = append(clientOpts, kgo.DialTLSConfig(tlsConfig))
	}

	resource, err := pool.RunWithOptions(runOpts, func(config *docker.HostConfig) {
		config.AutoRemove = true
	})
	require.NoError(t, err, "Failed to start container")

	t.Cleanup(func() {
		_ = pool.Purge(resource)
	})

	t.Logf("Advertised: %s | Seed brokers: %s", hostPort, resource.GetHostPort(exposedPort))
	clientOpts = append(clientOpts, kgo.SeedBrokers(resource.GetHostPort(exposedPort)))

	if _, ok := os.LookupEnv("CERBOS_DEBUG_KAFKA"); ok {
		ctx, cancelFunc := context.WithCancel(context.Background())
		go func() {
			if err := pool.Client.Logs(docker.LogsOptions{
				Context:      ctx,
				Container:    resource.Container.ID,
				OutputStream: os.Stdout,
				ErrorStream:  os.Stderr,
				Stdout:       true,
				Stderr:       true,
				Follow:       true,
			}); err != nil {
				cancelFunc()
			}
		}()
		t.Cleanup(cancelFunc)
	}

	client, err := kgo.NewClient(clientOpts...)
	require.NoError(t, err)

	require.NoError(t, pool.Retry(func() error {
		return client.Ping(context.Background())
	}), "Failed to connect to Kafka")

	// create topic
	_, err = kadm.NewClient(client).CreateTopic(context.Background(), 1, 1, nil, topic)
	require.NoError(t, err, "Failed to create Kafka topic")

	return hostPort
}

func fetchKafkaTopic(t *testing.T, uri string, topic string, tlsEnabled bool) ([]*kgo.Record, error) {
	kgoOptions := []kgo.Opt{kgo.SeedBrokers(uri)}
	if tlsEnabled {
		duration := 10 * time.Second
		skipVerify := false
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		tlsConfig, err := kafka.NewTLSConfig(ctx, duration, skipVerify, "testdata/valid/ca.crt", "testdata/valid/client/tls.crt", "testdata/valid/client/tls.key")
		if err != nil {
			return nil, err
		}

		kgoOptions = append(kgoOptions, kgo.DialTLSConfig(tlsConfig))
	}

	client, err := kgo.NewClient(kgoOptions...)
	if err != nil {
		return nil, err
	}

	client.AddConsumeTopics(topic)

	fetches := client.PollFetches(context.Background())
	return fetches.Records(), fetches.Err()
}

func newLog(m map[string]any) (audit.Log, error) {
	cfg, err := config.WrapperFromMap(m)
	if err != nil {
		return nil, err
	}
	return audit.NewLogFromConf(context.Background(), cfg)
}
