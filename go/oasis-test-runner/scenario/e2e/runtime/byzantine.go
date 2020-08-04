package runtime

import (
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// TODO: Consider referencing script names directly from the Byzantine node.

var (
	// Permutations generated in the epoch 2 election are
	// executor:              3 (w+s), 0 (w), 2 (b), 1 (i)
	// w = worker and not scheduler in first round
	// w+s = worker and scheduler in first round
	// b = backup
	// i = invalid
	//
	// For executor scripts, it suffices to be index 0.
	// For executor and scheduler scripts, it suffices to be index 3.
	// Indices are by order of node ID.

	// XXX: currently ByzantineDefaultIdentitySeed is used in all cases, to
	// ensure we are not the transaction scheduler of the round. Once straggling
	// schedulers are handled (without waiting for epoch transition), test that
	// case as well.

	// ByzantineExecutorHonest is the byzantine executor honest scenario.
	ByzantineExecutorHonest scenario.Scenario = newByzantineImpl("executor-honest", nil, oasis.ByzantineDefaultIdentitySeed)
	// ByzantineExecutorWrong is the byzantine executor wrong scenario.
	ByzantineExecutorWrong scenario.Scenario = newByzantineImpl("executor-wrong", []log.WatcherHandlerFactory{
		oasis.LogAssertNoTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertExecutionDiscrepancyDetected(),
	}, oasis.ByzantineDefaultIdentitySeed)
	// ByzantineExecutorStraggler is the byzantine executor straggler scenario.
	ByzantineExecutorStraggler scenario.Scenario = newByzantineImpl("executor-straggler", []log.WatcherHandlerFactory{
		oasis.LogAssertTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertExecutionDiscrepancyDetected(),
	}, oasis.ByzantineDefaultIdentitySeed)
)

type byzantineImpl struct {
	runtimeImpl

	script                     string
	identitySeed               string
	logWatcherHandlerFactories []log.WatcherHandlerFactory
}

func newByzantineImpl(script string, logWatcherHandlerFactories []log.WatcherHandlerFactory, identitySeed string) scenario.Scenario {
	return &byzantineImpl{
		runtimeImpl: *newRuntimeImpl(
			"byzantine/"+script,
			"simple-keyvalue-ops-client",
			[]string{"set", "hello_key", "hello_value"},
		),
		script:                     script,
		identitySeed:               identitySeed,
		logWatcherHandlerFactories: logWatcherHandlerFactories,
	}
}

func (sc *byzantineImpl) Clone() scenario.Scenario {
	return &byzantineImpl{
		runtimeImpl:                *sc.runtimeImpl.Clone().(*runtimeImpl),
		script:                     sc.script,
		identitySeed:               sc.identitySeed,
		logWatcherHandlerFactories: sc.logWatcherHandlerFactories,
	}
}

func (sc *byzantineImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// The byzantine node requires deterministic identities.
	f.Network.DeterministicIdentities = true
	// The byzantine scenario requires mock epochtime as the byzantine node
	// doesn't know how to handle epochs in which it is not scheduled.
	f.Network.EpochtimeMock = true
	// Change the default network log watcher handler factories if configured.
	if sc.logWatcherHandlerFactories != nil {
		f.Network.DefaultLogWatcherHandlerFactories = sc.logWatcherHandlerFactories
	}
	// Provision a Byzantine node.
	f.ByzantineNodes = []oasis.ByzantineFixture{
		{
			Script:          sc.script,
			IdentitySeed:    sc.identitySeed,
			Entity:          1,
			ActivationEpoch: 1,
		},
	}
	return f, nil
}

func (sc *byzantineImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.runtimeImpl.start(childEnv)
	if err != nil {
		return err
	}

	if err = sc.initialEpochTransitions(); err != nil {
		return err
	}

	return sc.wait(childEnv, cmd, clientErrCh)
}
