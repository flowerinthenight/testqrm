module github.com/flowerinthenight/testqrm

go 1.14

require (
	github.com/armon/go-metrics v0.3.9 // indirect
	github.com/fatih/color v1.12.0 // indirect
	github.com/flowerinthenight/dlock v0.0.0-20200707092122-a0e8f1144979
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/hashicorp/go-hclog v0.16.2 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-msgpack v1.1.5 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/raft v1.1.2
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/rqlite/rqlite v4.6.0+incompatible
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/sys v0.0.0-20210915083310-ed5796bab164 // indirect
	k8s.io/apimachinery v0.18.5
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog/v2 v2.3.0
)

// curl -s https://proxy.golang.org/k8s.io/api/@v/kubernetes-1.16.0.info | jq -r .Version
// curl -s https://proxy.golang.org/k8s.io/apimachinery/@v/kubernetes-1.16.0.info | jq -r .Version
// curl -s https://proxy.golang.org/k8s.io/client-go/@v/kubernetes-1.16.0.info | jq -r .Version
replace (
	github.com/hashicorp/raft => github.com/hashicorp/raft v1.1.1
	github.com/rqlite/rqlite => github.com/rqlite/rqlite v0.0.0-20200615182357-aed6484b0742
	k8s.io/api => k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190918160344-1fbdaa4c8d90
)
