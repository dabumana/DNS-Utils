package main

import (
	"log"
	"net"
	"strconv"

	"github.com/miekg/dns"
)

var domainsToAddresses map[string]string = map[string]string{
	"google.com.": "1.2.3.4",
	"not-a.xyz.":  "1.3.3.7",
	/* Add more use cases */
}

var domainsToMX map[string][]*dns.MX = map[string][]*dns.MX{
	"google.com.": {{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mail.google.com."}},
	"not-a.xyz.":  {{Hdr: dns.RR_Header{Name: "not-a.xyz.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mail.not-a.xyz."}},
	/* Add more use cases */
}

var domainsToCNAME map[string][]*dns.CNAME = map[string][]*dns.CNAME{
	"google.com": {{Hdr: dns.RR_Header{Name: "google.com", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "www.not-a.xyz"}},
	"not-a.xyz":  {{Hdr: dns.RR_Header{Name: "not-a.xyz", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "www.not-a.xyz"}},
	/* Add more use cases */
}

var domaintToCAA map[string][]*dns.CAA = map[string][]*dns.CAA{
	"google.com": {{Hdr: dns.RR_Header{Name: "google.com", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60}, Value: "m.google.com"}},
	"not-a.xyz":  {{Hdr: dns.RR_Header{Name: "not-a.xyz", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60}, Value: "m.not-a.xyz"}},
	/* Add more use cases */
}

type handler struct{}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		address, ok := domainsToAddresses[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(address),
			})
		}
		/* Add more use cases */
	case dns.TypeAAAA:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		address, ok := domainsToAddresses[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP(address),
			})
		}
		/* Add more use cases */
	case dns.TypeCNAME:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		address, ok := domainsToCNAME[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: address[0].String(),
			})
		}
		/* Add more use cases */
	case dns.TypeCAA:
		msg.Authoritative = false
		domain := msg.Question[0].Name
		address, ok := domaintToCAA[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.CAA{
				Hdr:   dns.RR_Header{Name: domain, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60},
				Value: address[0].Value,
			})
		}
		/* Add more use cases */
	case dns.TypeMX:
		msg.Authoritative = false
		domain := msg.Question[0].Name
		address, ok := domainsToMX[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.MX{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
				Mx:  address[0].Mx,
			})
		}
		/* Add more use cases */
	case dns.TypeTXT:
		msg.Authoritative = false
		domain := msg.Question[0].Name
		address, ok := domainsToAddresses[domain]
		if ok {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{address},
			})
		}
		/* Add more use cases */
	}

	w.WriteMsg(&msg)
}

func main() {
	srv := &dns.Server{Addr: ":" + strconv.Itoa(53), Net: "udp"}
	srv.Handler = &handler{}
	defer srv.Shutdown()
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set udp listener %s\n", err.Error())
	}
}
