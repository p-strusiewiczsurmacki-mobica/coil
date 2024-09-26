package e2e

import (
	"bytes"
	"fmt"

	coilv2 "github.com/cybozu-go/coil/v2/api/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/common/expfmt"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("coil-ipam-controller", func() {
	if testIPAM {
		It("should elect a leader instance of coil-controller", func() {
			kubectlSafe(nil, "-n", "kube-system", "get", "leases", "coil-ipam-leader")
		})

		It("should run the admission webhook", func() {
			By("trying to create an invalid AddressPool")
			_, err := kubectl(nil, "apply", "-f", "manifests/invalid_pool.yaml")
			Expect(err).Should(HaveOccurred())
		})

		It("should export metrics", func() {
			pods := &corev1.PodList{}
			getResourceSafe("kube-system", "pods", "", "app.kubernetes.io/component=coil-ipam-controller", pods)
			Expect(pods.Items).Should(HaveLen(2))

			node := pods.Items[0].Spec.NodeName
			out, err := runOnNode(node, "curl", "-sf", "http://localhost:9386/metrics")
			Expect(err).ShouldNot(HaveOccurred())

			mfs, err := (&expfmt.TextParser{}).TextToMetricFamilies(bytes.NewReader(out))
			Expect(err).NotTo(HaveOccurred())
			Expect(mfs).NotTo(BeEmpty())
		})

		It("should run garbage collector", func() {
			By("creating an orphaned AddressBlock")
			kubectlSafe(nil, "apply", "-f", "manifests/orphaned.yaml")

			By("checking the AddressBlock gets removed")
			Eventually(func() interface{} {
				abl := &coilv2.AddressBlockList{}
				err := getResource("", "addressblocks", "", "coil.cybozu.com/node=coil-worker100", abl)
				if err != nil {
					return err
				}
				return abl.Items
			}, 20).Should(BeEmpty())
		})
	}
})

var _ = Describe("coil-egress-controller", func() {
	if testEgress {
		It("should elect a leader instance of coil-controller", func() {
			kubectlSafe(nil, "-n", "kube-system", "get", "leases", "coil-egress-leader")
		})

		It("should export metrics", func() {
			pods := &corev1.PodList{}
			getResourceSafe("kube-system", "pods", "", "app.kubernetes.io/component=coil-egress-controller", pods)
			Expect(pods.Items).Should(HaveLen(2))

			node := pods.Items[0].Spec.NodeName

			out, err := runOnNode(node, "curl", "-sf", fmt.Sprintf("http://%s:9396/metrics", pods.Items[0].Status.PodIP))
			Expect(err).ShouldNot(HaveOccurred())

			mfs, err := (&expfmt.TextParser{}).TextToMetricFamilies(bytes.NewReader(out))
			Expect(err).NotTo(HaveOccurred())
			Expect(mfs).NotTo(BeEmpty())
		})
	}
})
