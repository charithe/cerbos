// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	badgerv4 "github.com/dgraph-io/badger/v4"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/audit/local"
	"github.com/cerbos/cerbos/internal/config"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
)

const (
	Backend = "hub"
)

var (
	SyncStatusPrefix   = []byte("bs")   // "b" for contiguity with audit log keys in LSM, "s" because "sync"
	AccessSyncPrefix   = []byte("bsac") // these need to be len(4) to correctly reuse `local.GenKey`
	DecisionSyncPrefix = []byte("bsde")
)

func init() {
	audit.RegisterBackend(Backend, func(_ context.Context, confW *config.Wrapper, decisionFilter audit.DecisionLogEntryFilter) (audit.Log, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, fmt.Errorf("failed to read hub audit log configuration: %w", err)
		}

		logger := zap.L().Named("auditlog").With(zap.String("backend", Backend))

		syncer, err := NewIngestSyncer(logger)
		if err != nil {
			return nil, err
		}

		return NewLog(conf, decisionFilter, syncer, logger)
	})
}

type Log struct {
	syncer IngestSyncer
	*local.Log
	logger           *zap.Logger
	filter           *AuditLogFilter
	pool             *pool.ContextPool
	cancel           context.CancelFunc
	minFlushInterval time.Duration
	flushTimeout     time.Duration
	maxBatchSize     int
	numGo            int
}

func NewLog(conf *Conf, decisionFilter audit.DecisionLogEntryFilter, syncer IngestSyncer, logger *zap.Logger) (*Log, error) {
	localLog, err := local.NewLog(&conf.Conf, decisionFilter)
	if err != nil {
		return nil, err
	}

	logger.Info("Extending audit log")

	minFlushInterval := conf.Ingest.MinFlushInterval
	maxBatchSize := int(conf.Ingest.MaxBatchSize)
	flushTimeout := conf.Ingest.FlushTimeout
	numGo := int(conf.Ingest.NumGoRoutines)

	filter, err := NewAuditLogFilter(conf.Mask)
	if err != nil {
		return nil, err
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	log := &Log{
		Log:              localLog,
		syncer:           syncer,
		logger:           logger,
		filter:           filter,
		minFlushInterval: minFlushInterval,
		flushTimeout:     flushTimeout,
		maxBatchSize:     maxBatchSize,
		numGo:            numGo,
		cancel:           cancelFn,
		pool:             pool.New().WithContext(ctx),
	}

	log.pool.Go(log.syncLoop)
	return log, nil
}

func (l *Log) WriteAccessLogEntry(ctx context.Context, record audit.AccessLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	if err := l.Log.WriteAccessLogEntry(ctx, func() (*auditv1.AccessLogEntry, error) {
		return rec, nil
	}); err != nil {
		return err
	}

	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return fmt.Errorf("invalid call ID: %w", err)
	}

	key := local.GenKey(AccessSyncPrefix, callID)
	value := local.GenKey(local.AccessLogPrefix, callID)

	return l.Write(ctx, key, value)
}

func (l *Log) WriteDecisionLogEntry(ctx context.Context, record audit.DecisionLogEntryMaker) error {
	rec, err := record()
	if err != nil {
		return err
	}

	if err := l.Log.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		return rec, nil
	}); err != nil {
		return err
	}

	callID, err := audit.ID(rec.CallId).Repr()
	if err != nil {
		return fmt.Errorf("invalid call ID: %w", err)
	}

	key := local.GenKey(DecisionSyncPrefix, callID)
	value := local.GenKey(local.DecisionLogPrefix, callID)

	return l.Write(ctx, key, value)
}

func (l *Log) syncLoop(ctx context.Context) error {
	ticker := time.NewTicker(l.minFlushInterval)
	for {
		select {
		case <-ticker.C:
			ticker.Stop()
			delay := l.schedule()
			ticker.Reset(delay)
		case <-ctx.Done():
			return nil
		}
	}
}

func (l *Log) schedule() time.Duration {
	l.logger.Log(zapcore.Level(-3), "Scheduling stream")
	if err := l.streamLogs(); err != nil {
		var ingestErr ErrIngestBackoff
		if errors.As(err, &ingestErr) {
			l.logger.Warn("svc-ingest issued backoff", zap.Error(err))
			if ingestErr.Backoff < l.minFlushInterval {
				return l.minFlushInterval
			}
			return ingestErr.Backoff
		}
		l.logger.Error("Audit log sync failed", zap.Error(err))
	}

	return l.minFlushInterval
}

func (l *Log) streamLogs() error {
	// We use two streams: one for access logs, and one for decision logs, as this allows us to
	// avoid the penalty of per-key string inspection when inferring the type down the line.
	ctx := context.Background()

	p := pool.New().WithContext(ctx).WithCancelOnError()
	p.Go(func(ctx context.Context) error {
		l.logger.Log(zapcore.Level(-2), "Streaming access logs")
		if err := l.streamPrefix(ctx, logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG, AccessSyncPrefix); err != nil {
			l.logger.Warn("Failed to stream access logs", zap.Error(err))
			return fmt.Errorf("failed to stream access logs: %w", err)
		}
		l.logger.Log(zapcore.Level(-2), "Finished streaming access logs")
		return nil
	})

	p.Go(func(ctx context.Context) error {
		l.logger.Log(zapcore.Level(-2), "Streaming decision logs")
		if err := l.streamPrefix(ctx, logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG, DecisionSyncPrefix); err != nil {
			l.logger.Warn("Failed to stream decision logs", zap.Error(err))
			return fmt.Errorf("failed to stream decision logs: %w", err)
		}
		l.logger.Log(zapcore.Level(-2), "Finished streaming decision logs")
		return nil
	})

	if err := p.Wait(); err != nil {
		l.logger.Warn("Failed to stream logs", zap.Error(err))
		return fmt.Errorf("failed to stream logs: %w", err)
	}
	return nil
}

var keysPool = &sync.Pool{}

func (l *Log) streamPrefix(ctx context.Context, kind logsv1.IngestBatch_EntryKind, prefix []byte) error {
	logger := l.logger.With(zap.Stringer("kind", kind))

	syncKeys := func(keys [][]byte) error {
		logger.Log(zapcore.Level(-3), "Syncing and deleting batch")
		if err := l.syncThenDelete(ctx, kind, keys); err != nil {
			return fmt.Errorf("failed to sync and delete logs: %w", err)
		}

		return nil
	}

	opts := badgerv4.DefaultIteratorOptions
	opts.Prefix = prefix
	opts.PrefetchValues = false
	return l.Db.View(func(txn *badgerv4.Txn) error {
		it := txn.NewIterator(opts)
		defer it.Close()

		var keys [][]byte
		if keysIface := keysPool.Get(); keysIface == nil {
			keys = make([][]byte, l.maxBatchSize)
		} else {
			keys = *(keysIface.(*[][]byte)) //nolint:forcetypeassert
		}
		defer keysPool.Put(&keys)

		var i int
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			if keys[i] == nil {
				keys[i] = make([]byte, len(item.Key()))
			} else {
				clear(keys[i])
			}
			copy(keys[i], item.Key())

			i++
			if i == l.maxBatchSize {
				if err := syncKeys(keys); err != nil {
					return err
				}

				i = 0
			}
		}

		return syncKeys(keys[:i])
	})
}

func (l *Log) syncThenDelete(ctx context.Context, kind logsv1.IngestBatch_EntryKind, syncKeys [][]byte) error {
	logger := l.logger.With(zap.Stringer("kind", kind))
	logger.Log(zapcore.Level(-3), "Getting ingest batch entries")
	entries, err := l.getIngestBatchEntries(syncKeys, kind)
	if err != nil {
		logger.Log(zapcore.Level(-2), "Failed to get ingest batch entries", zap.Error(err))
		return fmt.Errorf("failed to get ingest batch entries: %w", err)
	}

	if len(entries) == 0 {
		logger.Log(zapcore.Level(-3), "Ingest batch is empty")
		return nil
	}

	logger.Log(zapcore.Level(-3), "Generating audit ID")
	batchID, err := audit.NewID()
	if err != nil {
		return fmt.Errorf("failed to generate audit ID: %w", err)
	}

	{
		ctx, cancelFn := context.WithTimeout(ctx, l.flushTimeout)
		defer cancelFn()

		ingestBatch := &logsv1.IngestBatch{
			Id:      string(batchID),
			Entries: entries,
		}

		logger.Log(zapcore.Level(-3), "Filtering batch of "+strconv.Itoa(len(ingestBatch.Entries)))
		if err := l.filter.Filter(ingestBatch); err != nil {
			return fmt.Errorf("failed to filter batch: %w", err)
		}

		logger.Log(zapcore.Level(-3), "Syncing batch of "+strconv.Itoa(len(ingestBatch.Entries)))
		if err := l.syncer.Sync(ctx, ingestBatch); err != nil {
			return fmt.Errorf("failed to sync batch: %w", err)
		}
	}

	wb := l.Db.NewWriteBatch()
	defer wb.Cancel()

	logger.Log(zapcore.Level(-3), "Deleting synced keys")
	for _, k := range syncKeys {
		if err := wb.Delete(k); err != nil {
			if errors.Is(err, badgerv4.ErrDiscardedTxn) {
				wb.Cancel()
				wb = l.Db.NewWriteBatch()
				_ = wb.Delete(k)
			} else {
				return fmt.Errorf("failed to delete key: %w", err)
			}
		}
	}

	logger.Log(zapcore.Level(-3), "Flushing write batch")
	return wb.Flush()
}

func (l *Log) getIngestBatchEntries(syncKeys [][]byte, kind logsv1.IngestBatch_EntryKind) ([]*logsv1.IngestBatch_Entry, error) {
	entries := make([]*logsv1.IngestBatch_Entry, 0, len(syncKeys))
	if err := l.Db.Update(func(txn *badgerv4.Txn) error {
		for _, k := range syncKeys {
			syncItem, err := txn.Get(k)
			if err != nil {
				if errors.Is(err, badgerv4.ErrKeyNotFound) {
					continue
				}
				return err
			}

			var logKey []byte
			if err := syncItem.Value(func(v []byte) error {
				logKey = v
				return nil
			}); err != nil {
				return err
			}

			logItem, err := txn.Get(logKey)
			if err != nil {
				if errors.Is(err, badgerv4.ErrKeyNotFound) {
					continue
				}
				return err
			}

			var entry *logsv1.IngestBatch_Entry
			if err := logItem.Value(func(v []byte) error {
				switch kind {
				case logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG:
					accessLog := &auditv1.AccessLogEntry{}
					if err := accessLog.UnmarshalVT(v); err != nil {
						return err
					}

					entry = &logsv1.IngestBatch_Entry{
						Kind: logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG,
						Entry: &logsv1.IngestBatch_Entry_AccessLogEntry{
							AccessLogEntry: accessLog,
						},
						Timestamp: accessLog.Timestamp,
					}
				case logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG:
					decisionLog := &auditv1.DecisionLogEntry{}
					if err := decisionLog.UnmarshalVT(v); err != nil {
						return err
					}

					entry = &logsv1.IngestBatch_Entry{
						Kind: logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG,
						Entry: &logsv1.IngestBatch_Entry_DecisionLogEntry{
							DecisionLogEntry: decisionLog,
						},
						Timestamp: decisionLog.Timestamp,
					}
				case logsv1.IngestBatch_ENTRY_KIND_UNSPECIFIED:
					return errors.New("unspecified IngestBatch_EntryKind")
				}

				return nil
			}); err != nil {
				return err
			}

			entries = append(entries, entry)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return entries, nil
}

func (l *Log) Backend() string {
	return Backend
}

func (l *Log) Close() (outErr error) {
	l.cancel()
	outErr = errors.Join(outErr, l.pool.Wait())
	outErr = errors.Join(outErr, l.Db.Sync())
	outErr = errors.Join(outErr, l.Log.Close())
	return outErr
}
