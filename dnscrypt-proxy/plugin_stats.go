package main

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/gin-gonic/gin"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

const (
	cachedUpstream = "cached"
	maxSaveCount   = 10000
	maxTopCount    = 100
)

type PluginStat struct {
	webPgPath string

	db *badger.DB

	curr      *unit
	currMux   sync.RWMutex
	flushTime time.Time
}

func (p *PluginStat) Name() string {
	return "stat"
}

func (p *PluginStat) Description() string {
	return "Data statistics"
}

func (p *PluginStat) Init(proxy *Proxy) error {
	p.webPgPath = "./static/index.html"
	if proxy.WebPgPath != "" {
		p.webPgPath = proxy.WebPgPath
	}

	dbPath := proxy.StatDBPath
	if dbPath == "" {
		dbPath = ":memory:"
	}

	db, err := badger.Open(badger.DefaultOptions(dbPath))
	if err != nil {
		return fmt.Errorf("init stats plugin, open db err: %v", err)
	}
	p.db = db

	id := newUnitID()
	p.curr = newUnit(id)
	err = db.View(func(txn *badger.Txn) error {
		u := loadUnitFromDB(txn, id)
		if u == nil {
			return nil
		}

		p.curr.restore(u)
		return nil
	})
	if err != nil {
		return fmt.Errorf("init stats plugin, load unit err: %v", err)
	}

	go p.webServe()
	go p.flush()

	return nil
}

func (p *PluginStat) Drop() error {
	return nil
}

func (p *PluginStat) Reload() error {
	return nil
}

func (p *PluginStat) Eval(pluginsState *PluginsState, _ *dns.Msg) error {
	qName := pluginsState.qName

	var clientIPStr string
	switch pluginsState.clientProto {
	case "udp":
		clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
	case "tcp", "local_doh":
		clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
	default:
		// Ignore internal flow.
		return nil
	}

	var requestDuration time.Duration
	if !pluginsState.requestStart.IsZero() && !pluginsState.requestEnd.IsZero() {
		requestDuration = pluginsState.requestEnd.Sub(pluginsState.requestStart)
	}

	p.currMux.Lock()
	defer p.currMux.Unlock()

	p.curr.add(entry{
		domain:       StringQuote(qName),
		client:       clientIPStr,
		upstream:     StringQuote(pluginsState.serverName),
		upstreamTime: uint64(requestDuration / time.Millisecond),
	})

	return nil
}

func (p *PluginStat) flush() {
	ticker := time.NewTicker(time.Second)
	for ; true; <-ticker.C {
		p.doFlush()
	}
}

func (p *PluginStat) doFlush() {
	id := newUnitID()

	p.currMux.Lock()
	defer p.currMux.Unlock()

	u := p.curr
	if u == nil {
		p.curr = newUnit(id)
		return
	}

	if u.id == id {
		if time.Since(p.flushTime) >= time.Minute {
			goto flush
		}

		return
	}

	p.curr = newUnit(id)

flush:
	data, err := u.unitDB().serialize()
	if err != nil {
		dlog.Errorf("flush stat data, serialize err: %v", err)
		return
	}

	err = p.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(id2Key(u.id), data).WithTTL(30 * 24 * time.Hour)
		return txn.SetEntry(e)
	})
	if err != nil {
		dlog.Errorf("flush stat data, write db err: %v", err)
	}

	p.flushTime = time.Now()

	return
}

func (p *PluginStat) webServe() {
	gin.SetMode(gin.ReleaseMode)
	e := gin.Default()
	e.StaticFile("/", p.webPgPath)
	e.GET("/stat", p.StatHandler)
	err := e.Run(":5380")
	if err != nil {
		dlog.Errorf("stat plugin start web server err: %v", err)
	}
}

func (p *PluginStat) StatHandler(c *gin.Context) {
	timeStr := c.DefaultQuery("time", "24h")
	timeframe, err := parseDuration(timeStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	p.currMux.RLock()
	defer p.currMux.RUnlock()

	limit := uint32(timeframe.Hours())
	units := make([]*unitDB, 0, limit)
	curr := p.curr

	var currID uint32
	if curr == nil {
		currID = newUnitID()
	} else {
		currID = curr.id
		units = append(units, curr.unitDB())
	}

	txn := p.db.NewTransaction(true)
	defer txn.Discard()

	startID := currID - limit + 1 // +1 can include the current time.
	for i := startID; i != currID; i++ {
		u := loadUnitFromDB(txn, i)
		if u == nil {
			continue
		}

		units = append(units, u)
	}

	resp := buildResp(units)
	c.JSON(http.StatusOK, resp)
}

type Resp struct {
	TotalQuery             uint64              `json:"total_query"`
	TotalClient            uint64              `json:"total_client"`
	TotalDomain            uint64              `json:"total_domain"`
	TopDomain              []map[string]uint64 `json:"top_domain"`
	TopClient              []map[string]uint64 `json:"top_client"`
	TopUpstream            []map[string]uint64 `json:"top_upstream"`
	TopUpstreamAvgDuration []map[string]uint64 `json:"top_upstream_avg_time"`
}

func buildResp(units []*unitDB) *Resp {

	var (
		queryTotal       uint64
		domainMap        = make(map[string]uint64)
		clientMap        = make(map[string]uint64)
		upstreamMap      = make(map[string]uint64)
		upstreamDuration = make(map[string]uint64)
	)
	for _, u := range units {
		queryTotal += u.QueryTotal

		for _, v := range u.Domains {
			domainMap[v.Key] += v.Val
		}

		for _, v := range u.Clients {
			clientMap[v.Key] += v.Val
		}

		for _, v := range u.Upstreams {
			if v.Key == "-" {
				v.Key = cachedUpstream
			}
			upstreamMap[v.Key] += v.Val
		}

		for _, v := range u.UpstreamDuration {
			upstreamDuration[v.Key] += v.Val
		}
	}

	computeUpstreamAvgDuration := func() []map[string]uint64 {
		dm := make(map[string]uint64)
		for upstream, timeN := range upstreamMap {
			if upstream == cachedUpstream {
				continue
			}

			durationTotal := upstreamDuration[upstream]
			durationAvg := durationTotal / timeN
			dm[upstream] = durationAvg
		}

		pairs := convertMapToSlice(dm, maxTopCount)
		m := make([]map[string]uint64, 0, len(pairs))
		for i := len(pairs) - 1; i >= 0; i-- { // reverse
			p := pairs[i]
			m = append(m, map[string]uint64{p.Key: p.Val})
		}

		return m
	}

	return &Resp{
		TotalQuery:             queryTotal,
		TotalClient:            uint64(len(clientMap)),
		TotalDomain:            uint64(len(domainMap)),
		TopDomain:              buildTop(convertMapToSlice(domainMap, maxTopCount)),
		TopClient:              buildTop(convertMapToSlice(clientMap, maxTopCount)),
		TopUpstream:            buildTop(convertMapToSlice(upstreamMap, maxTopCount)),
		TopUpstreamAvgDuration: computeUpstreamAvgDuration(),
	}
}

func buildTop(ps []Pair) []map[string]uint64 {
	m := make([]map[string]uint64, 0, len(ps))
	for _, v := range ps {
		m = append(m, map[string]uint64{v.Key: v.Val})
	}

	return m
}

func loadUnitFromDB(txn *badger.Txn, id uint32) *unitDB {
	item, err := txn.Get(id2Key(id))
	if err != nil {
		dlog.Errorf("get unit from db err: %v", err)
		return nil
	}

	u := new(unitDB)
	err = item.Value(func(val []byte) error {
		return u.deserialize(val)
	})
	if err != nil {
		dlog.Errorf("load unit val err: %v", err)
		return nil
	}

	return u
}

func newUnit(id uint32) *unit {
	return &unit{
		id:           id,
		domains:      make(map[string]uint64),
		clients:      make(map[string]uint64),
		upstreams:    make(map[string]uint64),
		upstreamTime: make(map[string]uint64),
	}
}

func id2Key(id uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, id)
	return buf
}

type unit struct {
	id           uint32
	domains      map[string]uint64
	clients      map[string]uint64
	upstreams    map[string]uint64
	upstreamTime map[string]uint64
	queryTotal   uint64
}

func (u *unit) add(e entry) {
	u.domains[e.domain]++
	u.clients[e.client]++
	u.upstreams[e.upstream]++
	u.upstreamTime[e.upstream] += e.upstreamTime
	u.queryTotal++
}

func (u *unit) unitDB() *unitDB {
	return &unitDB{
		Domains:          convertMapToSlice(u.domains, maxSaveCount),
		Clients:          convertMapToSlice(u.clients, maxSaveCount),
		Upstreams:        convertMapToSlice(u.upstreams, maxSaveCount),
		UpstreamDuration: convertMapToSlice(u.upstreamTime, maxSaveCount),
		QueryTotal:       u.queryTotal,
	}
}

func (u *unit) restore(udb *unitDB) {
	u.domains = udb.Domains.toMap()
	u.clients = udb.Clients.toMap()
	u.upstreams = udb.Upstreams.toMap()
	u.upstreamTime = udb.UpstreamDuration.toMap()
	u.queryTotal = udb.QueryTotal
}

type entry struct {
	domain       string
	client       string
	upstream     string
	upstreamTime uint64
}

type Pair struct {
	Key string
	Val uint64
}

func (p1 Pair) compare(p2 Pair) int {
	pv1 := p1.Val
	pv2 := p2.Val

	switch {
	case pv1 > pv2:
		return -1
	case pv1 < pv2:
		return 1
	default:
		return 0
	}
}

type Set []Pair

func (s Set) toMap() map[string]uint64 {
	m := make(map[string]uint64, len(s))
	for _, p := range s {
		m[p.Key] = p.Val
	}

	return m
}

type unitDB struct {
	Domains          Set
	Clients          Set
	Upstreams        Set
	UpstreamDuration Set
	QueryTotal       uint64
}

func (udb *unitDB) serialize() ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(udb)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (udb *unitDB) deserialize(source []byte) error {
	err := gob.NewDecoder(bytes.NewReader(source)).Decode(udb)
	if err != nil {
		return err
	}
	return nil
}

func newUnitID() (id uint32) {
	const secsInHour = int64(time.Hour / time.Second)

	return uint32(time.Now().Unix() / secsInHour)
}

func convertMapToSlice(m map[string]uint64, max int) (s []Pair) {
	s = make([]Pair, 0, len(m))
	for k, v := range m {
		s = append(s, Pair{Key: k, Val: v})
	}

	slices.SortFunc(s, Pair.compare)

	if max > len(s) {
		max = len(s)
	}
	return s[:max]
}

func parseDuration(input string) (time.Duration, error) {
	unitMultipliers := map[string]time.Duration{
		"h": time.Hour,
		"d": time.Hour * 24,
	}

	if len(input) < 2 {
		return 0, errors.New("invalid duration format")
	}
	unit := string(input[len(input)-1])
	value := input[:len(input)-1]

	multiplier, ok := unitMultipliers[unit]
	if !ok {
		return 0, fmt.Errorf("unsupported time unit: %s", unit)
	}

	amount, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid duration value: %s", value)
	}

	return time.Duration(amount) * multiplier, nil
}
