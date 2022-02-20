package upstream

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"github.com/robertlestak/402/internal/db"
	"github.com/robertlestak/402/internal/utils"
	"github.com/robertlestak/402/pkg/auth"
	log "github.com/sirupsen/logrus"
)

func ListUpstreams(tenant string, page int, pageSize int) ([]Upstream, error) {
	var ups []Upstream
	var err error
	if tenant == "" {
		err = db.DB.Scopes(db.Paginate(page, pageSize)).Find(&ups).Error
	} else {
		err = db.DB.Scopes(db.Paginate(page, pageSize)).Where("tenant = ?", tenant).Find(&ups).Error
	}
	return ups, err
}

func HandleListUpstreamsForTenant(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action":  "HandleListUpstreamsForTenant",
		"request": r,
	})
	l.Debug("start")
	tenant := r.Header.Get(utils.HeaderPrefix() + "tenant")
	if tenant == "" {
		l.Info("tenant is empty")
		tenant = os.Getenv("DEFAULT_TENANT")
	}
	if !auth.RequestAuthorized(r) {
		l.Error("Not authorized")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}
	page := r.URL.Query().Get("page")
	pageSize := r.URL.Query().Get("pageSize")
	if page == "" {
		l.Debug("page is empty")
		page = "1"
	}
	if pageSize == "" {
		l.Debug("pageSize is empty")
		pageSize = "10"
	}
	pageI, err := strconv.Atoi(page)
	if err != nil {
		l.WithError(err).Error("Failed to parse page")
		http.Error(w, "Failed to parse page", http.StatusBadRequest)
		return
	}
	pageSizeI, err := strconv.Atoi(pageSize)
	if err != nil {
		l.WithError(err).Error("Failed to parse pageSize")
		http.Error(w, "Failed to parse pageSize", http.StatusBadRequest)
		return
	}
	if pageI < 1 {
		pageI = 1
	}
	if pageSizeI < 1 || pageSizeI > 100 {
		pageSizeI = 10
	}
	ups, err := ListUpstreams(tenant, pageI, pageSizeI)
	if err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ups); err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (u *Upstream) Delete() error {
	l := log.WithFields(log.Fields{
		"action":   "Delete",
		"upstream": u,
	})
	l.Debug("start")
	return db.DB.Where("name = ? and tenant = ?", u.Name, u.Tenant).Delete(u).Error
}

func HandleDeleteUpstreamForTenant(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action":  "HandleDeleteUpstreamForTenant",
		"request": r,
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
	r.Header.Set(utils.HeaderPrefix()+"tenant", *up.Tenant)
	if !auth.RequestAuthorized(r) {
		l.Error("Not authorized")
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}
	if err := up.Delete(); err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (u *Upstream) IsRootTenant() bool {
	if u.Tenant == nil {
		return false
	}
	return *u.Tenant == os.Getenv("ROOT_TENANT")
}

func (u *Upstream) GetByID() error {
	l := log.WithFields(log.Fields{
		"action":   "GetByID",
		"upstream": u,
	})
	l.Debug("start")
	return db.DB.Where("id = ?", u.ID).First(u).Error
}
