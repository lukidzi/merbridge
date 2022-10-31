/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpfs

import (
	"fmt"
	kumanet_ebpf "github.com/kumahq/kuma-net/ebpf"
	kumanet_config "github.com/kumahq/kuma-net/transparent-proxy/config"
)

var (
	MBConnect = &kumanet_ebpf.Program{
		Name:  "mb_connect",
		Flags: kumanet_ebpf.CgroupFlags,
		Cleanup: kumanet_ebpf.CleanPathsRelativeToBPFFS(
			"connect", // directory
			kumanet_ebpf.MapRelativePathCookieOrigDst,
			kumanet_ebpf.MapRelativePathNetNSPodIPs,
			kumanet_ebpf.MapRelativePathLocalPodIPs,
			kumanet_ebpf.MapRelativePathProcessIP,
		),
	}
	MBSockops = &kumanet_ebpf.Program{
		Name:  "mb_sockops",
		Flags: kumanet_ebpf.CgroupFlags,
		Cleanup: kumanet_ebpf.CleanPathsRelativeToBPFFS(
			"sockops",
			kumanet_ebpf.MapRelativePathCookieOrigDst,
			kumanet_ebpf.MapRelativePathProcessIP,
			kumanet_ebpf.MapRelativePathPairOrigDst,
			kumanet_ebpf.MapRelativePathSockPairMap,
		),
	}
	MBGetSockopts = &kumanet_ebpf.Program{
		Name:  "mb_get_sockopts",
		Flags: kumanet_ebpf.CgroupFlags,
		Cleanup: kumanet_ebpf.CleanPathsRelativeToBPFFS(
			"get_sockopts",
			kumanet_ebpf.MapRelativePathPairOrigDst,
		),
	}
	MBSendmsg = &kumanet_ebpf.Program{
		Name:  "mb_sendmsg",
		Flags: kumanet_ebpf.CgroupFlags,
		Cleanup: kumanet_ebpf.CleanPathsRelativeToBPFFS(
			"sendmsg",
			kumanet_ebpf.MapRelativePathCookieOrigDst,
		),
	}
	MBRecvmsg = &kumanet_ebpf.Program{
		Name:  "mb_recvmsg",
		Flags: kumanet_ebpf.CgroupFlags,
		Cleanup: kumanet_ebpf.CleanPathsRelativeToBPFFS(
			"recvmsg",
			kumanet_ebpf.MapRelativePathCookieOrigDst,
		),
	}
	MBRedir = &kumanet_ebpf.Program{
		Name:  "mb_redir",
		Flags: kumanet_ebpf.Flags(nil),
		Cleanup: kumanet_ebpf.CleanPathsRelativeToBPFFS(
			"redir",
			kumanet_ebpf.MapRelativePathSockPairMap,
		),
	}
	MBTc = &kumanet_ebpf.Program{
		Name: "mb_tc",
		Flags: func(
			cfg kumanet_config.Config,
			cgroup string,
			bpffs string,
		) ([]string, error) {
			var err error
			var iface string

			if cfg.Ebpf.TCAttachIface != "" && kumanet_ebpf.InterfaceIsUp(cfg.Ebpf.TCAttachIface) {
				iface = cfg.Ebpf.TCAttachIface
			} else if iface, err = kumanet_ebpf.GetNonLoopbackRunningInterface(); err != nil {
				return nil, fmt.Errorf("getting non-loopback interface failed: %v", err)
			}

			return kumanet_ebpf.Flags(map[string]string{
				"--iface": iface,
			})(cfg, cgroup, bpffs)
		},
		Cleanup: kumanet_ebpf.CleanPathsRelativeToBPFFS(
			kumanet_ebpf.MapRelativePathLocalPodIPs,
			kumanet_ebpf.MapRelativePathPairOrigDst,
		),
	}
)
