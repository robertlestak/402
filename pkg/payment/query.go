package payment

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/robertlestak/hpay/internal/db"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	log "github.com/sirupsen/logrus"
)

func GetPaymentByTxidNetwork(tenant, txid, network string) (*Payment, error) {
	var p Payment
	var err error
	if tenant != "" {
		err = db.DB.Where("txid = ? AND network = ? and tenant = ?", txid, network, tenant).First(&p).Error
	} else {
		err = db.DB.Where("txid = ? AND network = ?", txid, network).First(&p).Error
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func HandleGetPaymentByTenant(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action":  "HandleGetPaymentByTenant",
		"request": r,
	})
	l.Debug("start")
	vars := mux.Vars(r)
	txid := vars["txid"]
	network := vars["network"]
	if txid == "" {
		l.Error("txid is empty")
		http.Error(w, "txid is empty", http.StatusBadRequest)
		return
	}
	if network == "" {
		l.Error("network is empty")
		http.Error(w, "network is empty", http.StatusBadRequest)
		return
	}
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
	p, err := GetPaymentByTxidNetwork(tenant, txid, network)
	if err != nil {
		l.WithError(err).Error("Failed to get payment")
		http.Error(w, "Failed to get payment", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		l.WithError(err).Error("Failed to write response")
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func ListPayments(tenant string, page int, pageSize int) ([]Payment, error) {
	var payments []Payment
	var err error
	if tenant != "" {
		err = db.DB.Scopes(db.Paginate(page, pageSize)).Preload("Requests").Where("tenant = ?", tenant).Find(&payments).Error
	} else {
		err = db.DB.Scopes(db.Paginate(page, pageSize)).Preload("Requests").Find(&payments).Error
	}
	if err != nil {
		return nil, err
	}
	return payments, nil
}

func HandleListPaymentsForTenant(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "HandleListPaymentsForTenant",
	})
	l.Debug("start")
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
	payments, err := ListPayments(tenant, pageI, pageSizeI)
	if err != nil {
		l.WithError(err).Error("Failed to get payments")
		http.Error(w, "Failed to get payments", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(payments); err != nil {
		l.WithError(err).Error("Failed to write response")
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}
