package upstream

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/robertlestak/hpay/internal/cache"
	"github.com/robertlestak/hpay/internal/db"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var (
	// Upstreams contains the upstreams configuration
	Upstreams []Upstream
)

const (
	// MethodHTTP represents a HTTP HEAD request
	MethodHTTP HPayMethod = "http"
	// MethodHTML represents a HTML GET request
	MethodHTML HPayMethod = "html"
)

// HPayMethod represents the configured method for an upstream
type HPayMethod string

// UpstreamSelector represents the selectors for an upstream
type UpstreamSelector struct {
	Hosts   []*string          `json:"hosts" yaml:"hosts"`
	Paths   []*string          `json:"paths" yaml:"paths"`
	Headers *map[string]string `json:"headers" yaml:"headers"`
}

// Upstream represents an upstream
type Upstream struct {
	gorm.Model
	Tenant   *string           `gorm:"uniqueIndex:idx_tenant_name,not null" json:"tenant" yaml:"tenant"`
	Name     *string           `gorm:"uniqueIndex:idx_tenant_name,not null" json:"name" yaml:"name"`
	Endpoint *string           `gorm:"not null" json:"endpoint" yaml:"endpoint"`
	Method   *HPayMethod       `gorm:"not null" json:"method" yaml:"method"`
	Selector *UpstreamSelector `gorm:"type:jsonb" json:"selector" yaml:"selector"`
}

func (a UpstreamSelector) Value() (driver.Value, error) {
	return json.Marshal(a)
}

func (a *UpstreamSelector) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(b, &a)
}

// Init initializes the upstreams
func Init() error {
	l := log.WithFields(log.Fields{
		"action": "Upstream.Init",
	})
	l.Debug("start")
	if lerr := Load(); lerr != nil {
		l.Error(lerr)
		return lerr
	}
	go Loader()
	l.Debug("end")
	return nil
}

// Load loads the upstreams from the database
func Load() error {
	l := log.WithFields(log.Fields{
		"action": "Upstream.Load",
	})
	l.Debug("start")
	err := db.DB.Find(&Upstreams).Error
	if err != nil {
		l.Errorf("Find: %v", err)
		return err
	}
	l.Infof("Loaded %d upstreams", len(Upstreams))
	l.Debug("end")
	return nil
}

func (u *Upstream) Create() error {
	l := log.WithFields(log.Fields{
		"action": "Upstream.Create",
	})
	l.Debug("start")
	if err := db.DB.Create(u).Error; err != nil {
		l.Errorf("Create: %v", err)
		return err
	}
	l.Debug("end")
	return nil
}

func (u *Upstream) Update() error {
	l := log.WithFields(log.Fields{
		"action": "Upstream.Update",
	})
	l.Debug("start")
	if u.Name == nil || *u.Name == "" {
		l.Error("name is empty")
		return errors.New("name is empty")
	}
	if u.Tenant == nil || *u.Tenant == "" {
		l.Error("tenant is empty")
		return errors.New("tenant is empty")
	}
	res := db.DB.Where("name = ? and tenant = ?", u.Name, u.Tenant).Updates(u)
	if res.Error != nil {
		l.Errorf("Update: %v", res.Error)
		return res.Error
	} else if res.RowsAffected == 0 {
		if cerr := u.Create(); cerr != nil {
			l.Errorf("Create: %v", cerr)
			return cerr
		}
	}
	l.Debug("end")
	return nil
}

// Loader loads the upstreams from the database continually
func Loader() {
	l := log.WithFields(log.Fields{
		"action": "Upstream.Loader",
	})
	l.Debug("start")
	for {
		time.Sleep(time.Minute)
		l.Debug("loading upstreams")
		if err := Load(); err != nil {
			l.Fatalf("Load: %v", err)
		}
	}
}

// UpstreamForRequest inspects the incoming request, checks the selectors, and returns the matching upstream
func UpstreamForRequest(r *http.Request) (*Upstream, error) {
	l := log.WithFields(log.Fields{
		"action": "UpstreamForRequest",
	})
	l.Debug("start")
	if len(Upstreams) == 0 {
		l.Error("No upstreams specified")
		return nil, errors.New("no upstreams specified")
	}
	reqTenant := r.Header.Get("X-402-Tenant")
	if reqTenant == "" {
		l.Error("No tenant specified, using DEFAULT_TENANT")
		reqTenant = os.Getenv("DEFAULT_TENANT")
	}
	for _, u := range Upstreams {
		if *u.Tenant != reqTenant {
			continue
		}
		l.WithField("upstream", u.Endpoint).Debug("Checking upstream")
		selectorsMatch := make(map[string]bool)
		selectorsMatch["hosts"] = true
		selectorsMatch["paths"] = true
		selectorsMatch["headers"] = true
		wcstr := "*"
	RangeHosts:
		for _, s := range u.Selector.Hosts {
			if s == &wcstr {
				selectorsMatch["hosts"] = true
				break RangeHosts
			}
			if s != &r.Host {
				selectorsMatch["hosts"] = false
				break RangeHosts
			}
		}
	RangePaths:
		for _, s := range u.Selector.Paths {
			if s == &wcstr {
				selectorsMatch["paths"] = true
				break RangePaths
			}
			if s != &r.URL.Path {
				selectorsMatch["paths"] = false
				break RangePaths
			}
		}
	RangeHeaders:
		for k, v := range *u.Selector.Headers {
			if r.Header.Get(k) != v && v != "*" {
				selectorsMatch["headers"] = false
				break RangeHeaders
			}
		}
	RangeSelectors:
		for _, v := range selectorsMatch {
			if !v {
				break RangeSelectors
			}
		}
		l.WithFields(log.Fields{
			"selectorsMatch": selectorsMatch,
			"endpoint":       *u.Endpoint,
		}).Debug("Selectors match")
		return &u, nil
	}
	l.Error("No upstreams matched, using default")
	l.Debug("end")
	return &Upstreams[0], nil
}

// GetResourceMeta returns the meta data for the resource
func (u *Upstream) GetResourceMeta(r string) (map[string]string, error) {
	l := log.WithFields(log.Fields{
		"action":   "Upstream.GetResourceMeta",
		"resource": r,
	})
	l.Debug("start")
	switch *u.Method {
	case MethodHTTP:
		return u.HeadResource(r)
	case MethodHTML:
		return u.HTMLResource(r)
	default:
		l.Errorf("Unknown method: %s", *u.Method)
		return nil, errors.New("unknown method")
	}
}

// filterMeta filters the meta data for the resource to return
// only the 402 configured fields
func filterMeta(meta map[string]string) map[string]string {
	l := log.WithFields(log.Fields{
		"action": "filterMeta",
	})
	l.Debug("start")
	filtered := make(map[string]string)
	for k, v := range meta {
		lk := strings.ToLower(k)
		lp := strings.ToLower(utils.HeaderPrefix())
		if strings.HasPrefix(lk, lp) {
			filtered[lk] = v
		}
	}
	l.Debug("end")
	return filtered
}

// HeadResource makes a HEAD request to the upstream
// and returns the meta data
func (u *Upstream) HeadResource(r string) (map[string]string, error) {
	l := log.WithFields(log.Fields{
		"action":   "Upstream.HeadResource",
		"resource": r,
	})
	l.Debug("start")
	ep := *u.Endpoint
	up := ep + r
	var cacheDataStr string
	var cerr error
	headers := make(map[string]string)
	if cacheDataStr, cerr = cache.Get(up); cerr != nil || cacheDataStr == "" {
		l.WithField("cache", "miss").Debug("Cache miss")
	} else {
		l.WithField("cache", "hit").Debug("Cache hit")
		cerr = json.Unmarshal([]byte(cacheDataStr), &headers)
		if cerr != nil {
			l.Errorf("Unmarshal: %v", cerr)
			return nil, cerr
		}
		l.WithField("headers", headers).Debug("Headers from cache")
		l.Debug("end")
		return headers, nil
	}
	req, err := http.NewRequest("HEAD", up, nil)
	if err != nil {
		l.Errorf("NewRequest: %v", err)
		return nil, err
	}
	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		l.Errorf("Do: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	l.Debug("end")
	for k, v := range resp.Header {
		headers[strings.ToLower(k)] = v[0]
	}
	headers = filterMeta(headers)
	cacheData, err := json.Marshal(headers)
	if err != nil {
		l.Errorf("Marshal: %v", err)
		return nil, err
	}
	cache.Set(up, string(cacheData), cache.DefaultExpiration)
	return headers, nil
}

// HMTLResource makes a GET request to the upstream
// and returns the meta data from the body
func (u *Upstream) HTMLResource(r string) (map[string]string, error) {
	l := log.WithFields(log.Fields{
		"action":   "Upstream.HTMLResource",
		"resource": r,
	})
	l.Debug("start")
	ep := *u.Endpoint
	up := ep + r
	var cacheDataStr string
	var cerr error
	headers := make(map[string]string)
	if cacheDataStr, cerr = cache.Get(up); cerr != nil || cacheDataStr == "" {
		l.WithField("cache", "miss").Debug("Cache miss")
	} else {
		l.WithField("cache", "hit").Debug("Cache hit")
		cerr = json.Unmarshal([]byte(cacheDataStr), &headers)
		if cerr != nil {
			l.Errorf("Unmarshal: %v", cerr)
			return nil, cerr
		}
		l.WithField("headers", headers).Debug("Headers from cache")
		l.Debug("end")
		return headers, nil
	}
	req, err := http.NewRequest("GET", up, nil)
	if err != nil {
		l.Errorf("NewRequest: %v", err)
		return nil, err
	}
	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		l.Errorf("Do: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	defer l.Debug("end")
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		l.Errorf("NewDocumentFromReader: %v", err)
		return nil, err
	}
	doc.Find("meta").Each(func(i int, s *goquery.Selection) {
		var key string
		var val string
		var ok bool
		if key, ok = s.Attr("name"); !ok {
			l.Debug("No name attribute")
		}
		if val, ok = s.Attr("content"); !ok {
			l.Debug("No content attribute")
		}
		if key != "" && val != "" {
			headers[key] = val
		}
	})
	headers = filterMeta(headers)
	cacheData, err := json.Marshal(headers)
	if err != nil {
		l.Errorf("Marshal: %v", err)
		return nil, err
	}
	cache.Set(up, string(cacheData), cache.DefaultExpiration)
	return headers, nil
}

// PurgeCache purges the cache for the resource
func (u *Upstream) PurgeCache(r string) error {
	l := log.WithFields(log.Fields{
		"action":   "Upstream.PurgeCache",
		"resource": r,
	})
	l.Debug("start")
	ep := *u.Endpoint
	/*
		req, err := http.NewRequest("PURGE", ep+r, nil)
		if err != nil {
			l.Errorf("NewRequest: %v", err)
			return err
		}
		c := &http.Client{}
		resp, err := c.Do(req)
		if err != nil {
			l.Errorf("Do: %v", err)
			return err
		}
		defer resp.Body.Close()
	*/
	if cerr := cache.Del(ep + r); cerr != nil {
		l.Errorf("cache.Del: %v", cerr)
		return cerr
	}
	l.Debug("end")
	return nil
}

// HandlePurgeResource handles the PURGE request
func HandlePurgeResource(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "HandlePurgeResource",
	})
	l.Debug("start")
	up, err := UpstreamForRequest(r)
	if err != nil {
		l.Errorf("UpstreamForRequest: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t := utils.AuthToken(r)
	if t == "" {
		l.Error("No auth token")
		http.Error(w, "No auth token", http.StatusUnauthorized)
		return
	}
	if !auth.TokenIsRoot(t) {
		l.Error("Not root")
		http.Error(w, "Not root", http.StatusUnauthorized)
		return
	}
	resource := r.FormValue("resource")
	if err := up.PurgeCache(resource); err != nil {
		l.Errorf("Upstream.PurgeCache: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	l.Debug("end")
	w.WriteHeader(http.StatusOK)
}

func (u *Upstream) Validate() error {
	l := log.WithFields(log.Fields{
		"action": "Upstream.Validate",
	})
	l.Debug("start")
	if u == nil {
		l.Error("Upstream is nil")
		return errors.New("upstream is nil")
	}
	if u.Endpoint == nil {
		l.Error("No endpoint")
		return errors.New("no endpoint")
	}
	if u.Name == nil || *u.Name == "" {
		l.Error("No name")
		return errors.New("no name")
	}
	if u.Tenant == nil || *u.Tenant == "" {
		l.Error("No tenant")
		return errors.New("no tenant")
	}
	l.Debug("end")
	return nil
}

func HandleUpdateUpstream(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "HandleUpdateUpstream",
	})
	l.Debug("start")
	up := &Upstream{}
	defer l.Debug("end")
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(up); err != nil {
		l.Errorf("json.NewDecoder: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	l.WithField("upstream", up).Debug("Upstream")
	if err := up.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := utils.AuthToken(r)
	if token == "" {
		l.Error("No auth token")
		http.Error(w, "No auth token", http.StatusUnauthorized)
		return
	}
	// set to false if we are relying on middleware to validate tokens
	validateToken := false
	if !auth.TokenOwnsTenant(token, *up.Tenant, validateToken) {
		l.Error("Not owner")
		http.Error(w, "Not owner", http.StatusUnauthorized)
		return
	}
	if err := up.Update(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func ListTenants() ([]string, error) {
	l := log.WithFields(log.Fields{
		"action": "ListTenants",
	})
	l.Debug("start")
	var tenants []string
	err := db.DB.Raw("SELECT DISTINCT tenant FROM upstreams").Scan(&tenants).Error
	if err != nil {
		l.Errorf("DB.Exec: %v", err)
		return nil, err
	}
	l.Debug("end")
	return tenants, nil
}
