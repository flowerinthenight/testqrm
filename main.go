package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	goflag "flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/flowerinthenight/dlock"
	"github.com/golang/glog"
	"github.com/hashicorp/raft"
	"github.com/rqlite/rqlite/cluster"
	httpd "github.com/rqlite/rqlite/http"
	"github.com/rqlite/rqlite/store"
	"github.com/rqlite/rqlite/tcp"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

var version = "?"

var (
	rootCmd = &cobra.Command{
		Use:              "testqrm",
		Short:            "testqrm",
		Long:             "A testqrm test.",
		PersistentPreRun: func(cmd *cobra.Command, args []string) { goflag.Parse() },
	}
)

func init() {
	rootCmd.AddCommand(RunCmd())
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
}

func k8sclient() *kubernetes.Clientset {
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	return client
}

type Sophie struct {
	locker        *dlock.K8sLock
	str           *store.Store
	id            string
	nodeCleanupOn int32
}

type stats struct {
	Store struct {
		Leader struct {
			Addr string `json:"addr"`
		} `json:"leader"`
		Nodes []store.Server `json:"nodes"`
	} `json:"store"`
}

// func (s *Sophie) tryLock(ctx context.Context) bool {
// 	client := k8sclient()
// 	var leader int32

// 	go func() {
// 		// We use the Lease lock type since edits to Leases are less common
// 		// and fewer objects in the cluster watch "all Leases".
// 		lock := &resourcelock.LeaseLock{
// 			LeaseMeta: metav1.ObjectMeta{
// 				Name:      "testqrm",
// 				Namespace: "default",
// 			},
// 			Client:     client.CoordinationV1(),
// 			LockConfig: resourcelock.ResourceLockConfig{Identity: s.id},
// 		}

// 		// Start the leader election code loop.
// 		leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
// 			Lock:            lock,
// 			ReleaseOnCancel: true,
// 			LeaseDuration:   30 * time.Second,
// 			RenewDeadline:   15 * time.Second,
// 			RetryPeriod:     5 * time.Second,
// 			Callbacks: leaderelection.LeaderCallbacks{
// 				OnStartedLeading: func(ctx context.Context) { atomic.StoreInt32(&leader, 1) },
// 				OnStoppedLeading: func() {},
// 				OnNewLeader: func(identity string) {
// 					if identity == s.id {
// 						klog.Infof("%v just got the lock", identity)
// 					}
// 				},
// 			},
// 		})
// 	}()

// 	quit, _ := context.WithCancel(ctx)
// 	<-quit.Done()
// 	return atomic.LoadInt32(&leader) == 1
// }

func (s *Sophie) nodeCleanup(ctx context.Context) {
	if !s.str.IsLeader() || atomic.LoadInt32(&s.nodeCleanupOn) == 1 {
		return
	}

	atomic.StoreInt32(&s.nodeCleanupOn, 1)
	invalids := make(map[string]int)
	tick := time.NewTicker(time.Minute)
	quit, _ := context.WithCancel(ctx)
	for {
		select {
		case <-tick.C:
			var nodes []store.Server
			n, _ := s.str.Nodes()
			for _, x := range n {
				nodes = append(nodes, *x)
			}

			for _, v := range nodes {
				valid := isNode(v.ID)
				if !valid {
					invalids[v.ID] = invalids[v.ID] + 1
				}
			}
			klog.Infof("nodechecks: %v", invalids)
			if len(invalids) > 0 {
				for id, cnt := range invalids {
					if cnt > 1 {
						err := s.str.Remove(id)
						if err != nil {
							klog.Error(err)
						} else {
							delete(invalids, id)
						}
					}
				}
			}
		case <-quit.Done():
			return
		}
	}
}

func (s *Sophie) leasee() string {
	var ret string
	client := k8sclient()
	lease, err := client.CoordinationV1().Leases("default").Get("testqrm", metav1.GetOptions{})
	if err != nil {
		return ret
	}

	if lease.Spec.HolderIdentity != nil {
		ret = *lease.Spec.HolderIdentity
	}

	return ret
}

func (s *Sophie) stats(ip string) *stats {
	ldrIp := ip
	if ldrIp == "" {
		ldrIp = s.leasee()
	}

	if ldrIp == "" {
		return nil
	}

	u := fmt.Sprintf("http://%v:8080/status", ldrIp)
	resp, err := http.Get(u)
	if err != nil {
		return nil
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var sts stats
	err = json.Unmarshal(body, &sts)
	if err != nil {
		return nil
	}

	return &sts
}

func pods() []string {
	var ret []string
	ips, err := net.LookupIP("testqrm-headless.default.svc.cluster.local")
	if err != nil {
		return ret
	}

	for _, ip := range ips {
		ret = append(ret, ip.String())
	}

	return ret
}

func inpods(id string) bool {
	for _, ip := range pods() {
		if ip == id {
			return true
		}
	}

	return false
}

func isNode(ip string) bool {
	u := fmt.Sprintf("http://%v:8080/status", ip)
	resp, err := http.Get(u)
	if err != nil {
		return false
	}
	if resp.StatusCode == http.StatusOK {
		return true
	}
	return false
}

func startHTTPService(str *store.Store) error {
	// Create HTTP server and load authentication information if required.
	var s *httpd.Service
	s = httpd.New(os.Getenv("MY_POD_IP")+":8080", str, nil)
	s.BuildInfo = map[string]interface{}{
		"commit":     "0",
		"branch":     "0",
		"version":    "0",
		"build_time": "0",
	}
	return s.Start()
}

// 8080=http/join; 8081=raft
func run(quit context.Context, done chan error) {
	id := os.Getenv("MY_POD_IP")
	klog.Infof("nodeid: %v", id)
	var found bool
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second * 1)
		if inpods(id) {
			found = true
			break
		}
	}

	if !found {
		klog.Fatalf("cannot find self in pods")
	}

	klog.Infof("pods: %v", pods())
	dataPath := "sophie"
	tn := tcp.NewTransport()
	if err := tn.Open(id + ":8081"); err != nil {
		klog.Fatalf("failed to open internode network layer: %s", err)
	}

	dataPath, err := filepath.Abs(dataPath)
	if err != nil {
		klog.Fatalf("failed to determine absolute data path: %s", err)
	}

	dbConf := store.NewDBConfig("", true)
	str := store.New(tn, &store.StoreConfig{DBConf: dbConf, Dir: dataPath, ID: id})

	sophie := &Sophie{str: str, id: id}

	var lead int32
	lockquit, lockcancel := context.WithTimeout(context.TODO(), time.Minute)

	sophie.locker = dlock.NewK8sLock(id, "testqrm", dlock.WithLeaseDuration(time.Second*30),
		dlock.WithStartCallback(func(ctx context.Context) {
			atomic.StoreInt32(&lead, 1)
			klog.Info("got the lock")
		}),
		dlock.WithNewLeaderCallback(func(identity string) {
			if identity == id {
				klog.Infof("got the lock: %v", identity)
			}
		}),
	)

	sophie.locker.Lock(lockquit)
	leader := atomic.LoadInt32(&lead) == 1
	if !leader {
		klog.Infof("give up leadership attempt: %v", id)
		lockcancel()
	}

	// Set optional parameters on store.
	str.RaftLogLevel = "INFO"
	str.ShutdownOnRemove = false
	str.SnapshotThreshold = 8192
	str.SnapshotInterval, _ = time.ParseDuration("30s")
	str.HeartbeatTimeout, _ = time.ParseDuration("1s")
	str.ElectionTimeout, _ = time.ParseDuration("1s")
	str.ApplyTimeout, _ = time.ParseDuration("10s")

	// Determine join addresses, if necessary.
	ja, err := store.JoinAllowed(dataPath)
	if err != nil {
		klog.Fatalf("unable to determine if join permitted: %s", err)
	}

	var joins []string
	if ja {
		for _, ip := range pods() {
			joins = append(joins, fmt.Sprintf("http://%v:8080", ip))
		}
	} else {
		klog.Info("node is already member of cluster, skip determining join addresses")
	}

	if err := str.Open(leader); err != nil {
		klog.Fatalf("failed to open store: %s", err.Error())
	}

	quit0, _ := context.WithCancel(quit)
	ldrCh := make(chan raft.Observation)
	fltr := func(o *raft.Observation) bool { return true }

	obv := raft.NewObserver(ldrCh, true, fltr)
	go func() {
		for {
			select {
			case m := <-ldrCh:
				klog.Info("observer raw:", m)
				switch m.Data.(type) {
				case raft.LeaderObservation:
					if strings.Split(string(m.Raft.Leader()), ":")[0] != id {
						continue
					}

					go func() { // attempt infinite lock, till death
						klog.Infof("[next] attempt next lock: %v", id)
						nxtquit, _ := context.WithCancel(quit)
						sophie.locker.Lock(nxtquit)
					}()

					klog.Infof("leader (from actual Raft obj): %v, me=true", m.Raft.Leader())
					go sophie.nodeCleanup(quit)
				case raft.PeerObservation:
					v := m.Data.(raft.PeerObservation)
					me := id == string(v.Peer.ID)
					klog.Infof("peer observation: removed=%v, peer=%v, me=%v", v.Removed, v.Peer, me)
				case raft.RaftState:
					v := m.Data.(raft.RaftState)
					klog.Infof("raftstate observation: %v", v.String())
				}
			case <-quit0.Done():
				return
			}
		}
	}()

	str.RegisterObserver(obv)

	tick := time.NewTicker(time.Second * 30)
	quit1, _ := context.WithCancel(quit)
	go func() {
		for {
			select {
			case <-tick.C:
				me := id == strings.Split(str.LeaderAddr(), ":")[0]
				var nodes []store.Server
				n, _ := str.Nodes()
				for _, x := range n {
					nodes = append(nodes, *x)
				}

				klog.Infof("leader=%v, nodes=%v, me? %v", str.LeaderAddr(), len(nodes), me)
				ip := strings.Split(str.LeaderAddr(), ":")[0]
				sts := sophie.stats(ip)
				klog.Infof("%v, stats=%+v", ip, sts)
			case <-quit1.Done():
				return
			}
		}
	}()

	// Prepare metadata for join command.
	apiAdv := id + ":8080"
	meta := map[string]string{"api_addr": apiAdv}
	var joined bool

	voter := true
	sts := sophie.stats("")
	if sts != nil {
		if len(sts.Store.Nodes) >= 3 {
			voter = false
		}
	}

	// Execute any requested join operation.
	if !leader {
		for _, join := range joins {
			if fmt.Sprintf("http://%v:8080", id) == join {
				klog.Infof("skip, don't join to self: %v", id)
				continue // don't join to our own ip
			}

			ss := []string{join}
			klog.Info("join addresses are:", ss)
			advAddr := id + ":8081"
			joinDur, _ := time.ParseDuration("5s")
			tlsConfig := tls.Config{InsecureSkipVerify: false}
			if j, err := cluster.Join(ss, str.ID(), advAddr, voter, meta, 1, joinDur, &tlsConfig); err != nil {
				klog.Infof("failed to join cluster at %s: %s", joins, err.Error())
				continue
			} else {
				klog.Infof("successfully joined cluster at %v", j)
				joined = true
			}
		}
	} else {
		klog.Info("no join addresses set")
		joined = true
	}

	if !joined {
		log.Fatalf("failed to join")
	}

	// Wait until the store is in full consensus.
	openTimeout, err := time.ParseDuration("120s")
	if err != nil {
		klog.Fatalf("failed to parse Raft open timeout: %s", err.Error())
	}

	str.WaitForLeader(openTimeout)
	str.WaitForApplied(openTimeout)

	klog.Infof("pod=%v, leader=%v", id, str.LeaderAddr())

	go sophie.nodeCleanup(quit)

	// Start the HTTP API server.
	if err := startHTTPService(str); err != nil {
		klog.Fatalf("failed to start HTTP server: %s", err.Error())
	}

	<-quit.Done()
	lockcancel()

	if !str.IsLeader() {
		klog.Infof("attempt remove self (%v) from cluster", id)
		// str.Remove(id)

		func() {
			client := &http.Client{}
			ldrIp := strings.Split(str.LeaderAddr(), ":")[0]
			u := fmt.Sprintf("http://%v:8080/remove", ldrIp)
			m := map[string]interface{}{"id": ldrIp}
			b, _ := json.Marshal(m)
			req, err := http.NewRequest("DELETE", u, bytes.NewBuffer(b))
			if err != nil {
				klog.Error(err)
				return
			}

			// Fetch Request
			resp, err := client.Do(req)
			if err != nil {
				klog.Error(err)
				return
			}

			klog.Infof("DELETE %v: %v", ldrIp, resp.Status)
		}()

		tm, _ := context.WithTimeout(context.TODO(), time.Second*30)
		<-tm.Done()
	}

	klog.Info("testqrm stopped")
	done <- nil

	if err := str.Close(true); err != nil {
		klog.Infof("failed to close store: %s", err.Error())
	}

	klog.Info("testqrm end")
}

func RunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "run testqrm",
		Long:  "Run testqrm as a long-running service.",
		RunE: func(cmd *cobra.Command, args []string) error {
			defer func(begin time.Time) {
				glog.Infof("stop testqrm after %v", time.Since(begin))
			}(time.Now())

			glog.Infof("start testqrm on %v", time.Now())

			quit, cancel := context.WithCancel(context.TODO())
			done := make(chan error)
			go run(quit, done)

			go func() {
				sigch := make(chan os.Signal)
				signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
				glog.Info(<-sigch)
				cancel()
			}()

			return <-done
		},
	}

	return cmd
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		glog.Fatalf("%v", err)
	}
}
