module github.com/flowerinthenight/testqrm

go 1.14

require (
	github.com/PuerkitoBio/goquery v1.5.1 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/hashicorp/raft v1.1.2
	github.com/rqlite/rqlite v4.6.0+incompatible
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e // indirect
	k8s.io/api v0.18.5 // indirect
	k8s.io/apimachinery v0.18.5
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog/v2 v2.3.0
	k8s.io/utils v0.0.0-20200619165400-6e3d28b6ed19 // indirect
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
