package sqlite

import (
    "context"
    "database/sql"
    "fmt"
    "strings"

    "github.com/coredns/caddy"
    "github.com/coredns/coredns/core/dnsserver"
    "github.com/coredns/coredns/plugin"
    "github.com/miekg/dns"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/net/publicsuffix"
)

type SqlitePlugin struct {
    Next plugin.Handler
    DB   *sql.DB
}

func defaultAns(w dns.ResponseWriter, r *dns.Msg, qName string) (int, error) {
    m := new(dns.Msg)
    m.SetReply(r)
    rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN A 91.99.160.200", qName))
    if err != nil {
           panic(err)
    }
    m.Answer = append(m.Answer, rr)

    rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN AAAA 2a01:4f8:1c0c:6ab1::1", qName))
    if err != nil {
           panic(err)
    }
    m.Answer = append(m.Answer, rr)
    w.WriteMsg(m)
    return dns.RcodeSuccess, nil
}

func (s SqlitePlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    q := r.Question[0]

    fqdn := strings.ToLower(strings.TrimSuffix(q.Name, "."))
    qType := dns.TypeToString[q.Qtype]

    domain, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
    if err != nil {
        fmt.Println("sqlite: Bad eTLD+1")
        return defaultAns(w, r, q.Name)
        //return dns.RcodeServerFailure, err
    }
    subdomain := "@"
    if len(fqdn) > len(domain) {
        subdomain = fqdn[:len(fqdn)-len(domain)-1]
    }

    fmt.Println(fmt.Sprintf("sqlite: type='%s', domain='%s', subdomain='%s'", qType, domain, subdomain))
    rows, err := s.DB.Query("SELECT type, value FROM records WHERE apex = ? AND type = ? AND (subdomain = ? OR subdomain = '*')", domain, qType, subdomain)
    if err != nil {
        fmt.Println("sqlite: bad sql stmt", err)
        return defaultAns(w, r, q.Name)
    }
    defer rows.Close()

    var rowFound = false
    m := new(dns.Msg)
    m.SetReply(r)
    for rows.Next() {
        if !rowFound {
            rowFound = true
        }
        var typ string
        var data string
        if err := rows.Scan(&typ, &data); err != nil {
            fmt.Println("sqlite: Erro rows.Scan", err)
            continue
        }
        fmt.Println("sqlite: ServeDNS row", q.Name, typ, data)
        rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN %s %s", q.Name, typ, data))
        if err != nil {
            fmt.Println("sqlite: Erro constructing ans", err)
            continue
        }
        m.Answer = append(m.Answer, rr)
    }
    if !rowFound {
        return defaultAns(w, r, q.Name)
    }
    w.WriteMsg(m)
    return dns.RcodeSuccess, nil
}

func (s SqlitePlugin) Name() string { return "sqlite" }

func setup(c *caddy.Controller) error {
    var dbPath string
    for c.Next() {
        args := c.RemainingArgs()
        if len(args) != 1 {
                return c.ArgErr()
        }
        dbPath = "file:" + args[0] + "?_query_only=yes"
        fmt.Println("sqlite: serving from", dbPath)
    }

    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return err
    }

    dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
        return &SqlitePlugin{
            Next: next,
            DB:   db,
        }
    })
    return nil
}

func init() {
    plugin.Register("sqlite", setup)
}
