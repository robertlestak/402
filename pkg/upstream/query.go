package upstream

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"github.com/robertlestak/hpay/internal/db"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
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
	token := utils.AuthToken(r)
	if token == "" {
		l.Error("token is empty")
		http.Error(w, "token is empty", http.StatusUnauthorized)
		return
	}
	verified := true
	if !auth.TokenOwnsTenant(token, tenant, verified) {
		l.Error("token does not own tenant")
		http.Error(w, "token does not own tenant", http.StatusUnauthorized)
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
