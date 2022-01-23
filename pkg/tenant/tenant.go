package tenant

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/robertlestak/hpay/internal/db"
	"github.com/robertlestak/hpay/internal/utils"
	"github.com/robertlestak/hpay/pkg/auth"
	"github.com/robertlestak/hpay/pkg/hpay"
	"github.com/robertlestak/hpay/pkg/payment"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type Tenant struct {
	gorm.Model
	Name         string `gorm:"unique_index"`
	Email        string
	AccessPlanID uint
}

func (t *Tenant) Validate() error {
	l := log.WithFields(log.Fields{
		"package": "tenant",
		"action":  "Tenant.Validate",
	})
	l.Debug("start")
	if t.Name == os.Getenv("ROOT_TENANT") {
		l.Info("root tenant")
		return errors.New("root tenant")
	} else if t.Name == "" {
		l.Info("empty name")
		return errors.New("empty name")
	} else if t.Name == os.Getenv("DEFAULT_TENANT") {
		l.Info("default tenant")
		return errors.New("default tenant")
	} else if t.Name == "402" {
		l.Info("402 tenant")
		return errors.New("402 tenant")
	}
	l.Debug("end")
	return nil
}

func (t *Tenant) Create() error {
	return db.DB.Create(t).Error
}

func (t *Tenant) Update() error {
	l := log.WithFields(log.Fields{
		"action": "Tenant.Update",
	})
	l.Debug("start")
	if t.Name == "" {
		l.Error("name is empty")
		return errors.New("name is empty")
	}
	if err := t.Validate(); err != nil {
		l.Error("validation error: ", err)
		return err
	}
	res := db.DB.Where("name = ?", t.Name).Updates(t)
	if res.Error != nil {
		l.Errorf("Update: %v", res.Error)
		return res.Error
	} else if res.RowsAffected == 0 {
		if cerr := t.Create(); cerr != nil {
			l.Errorf("Update: %v", cerr)
			return cerr
		}
	}
	l.WithField("tenant", t).Debug("Tenant updated")
	l.Debug("end")
	return nil
}

func (t *Tenant) GetByName() error {
	return db.DB.Where("name = ?", t.Name).First(t).Error
}

func HandleCreateTenant(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"package": "tenant",
		"action":  "HandleCreateTenant",
	})
	l.Debug("start")
	defer l.Debug("end")
	vars := mux.Vars(r)
	tenant := vars["tenant"]
	t := &Tenant{Name: tenant}
	var plan string
	var ok bool
	if plan, ok = vars["plan"]; !ok {
		plan = os.Getenv("DEFAULT_PLAN_NAME")
	}
	r.Header.Set(utils.HeaderPrefix()+"tenant", tenant)
	if !auth.RequestAuthorized(r) {
		l.Debug("unauthorized")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tokens := utils.AuthTokens(r)
	var userOwnsPlan bool
	for _, t := range tokens {
		_, cl, err := auth.ValidateJWT(t)
		if err != nil {
			l.Error("error validating token: ", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if pid, ok := cl["pid"]; ok {
			if pid == plan {
				userOwnsPlan = true
				break
			}
		}
	}
	if !userOwnsPlan {
		l.Error("user does not own plan")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ap := &AccessPlan{Name: plan}
	if err := ap.GetByName(); err != nil {
		l.Error("error getting access plan: ", err)
		http.Error(w, "error getting access plan", http.StatusInternalServerError)
		return
	}
	if ap.ID == 0 {
		l.Error("access plan not found")
		http.Error(w, "access plan not found", http.StatusNotFound)
		return
	}
	t.AccessPlanID = ap.ID
	if err := t.GetByName(); err != nil && err != gorm.ErrRecordNotFound {
		l.Error("error getting tenant: ", err)
		http.Error(w, "error getting tenant", http.StatusInternalServerError)
		return
	} else if err == gorm.ErrRecordNotFound {
		l.WithField("tenant", tenant).Debug("tenant not found")
		if cerr := t.Create(); cerr != nil {
			l.Error("error creating tenant: ", cerr)
			http.Error(w, "error creating tenant", http.StatusInternalServerError)
		}
		l.WithField("tenant", tenant).Debug("tenant created")
		w.WriteHeader(http.StatusCreated)
		return
	}
	l.WithField("tenant", t).Debug("tenant found")
	if err := t.Update(); err != nil {
		l.Error("error updating tenant: ", err)
		http.Error(w, "error updating tenant", http.StatusInternalServerError)
	}
	l.WithField("tenant", t).Debug("tenant updated")
	w.WriteHeader(http.StatusCreated)
}

func HandleGetTenant(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"package": "tenant",
		"action":  "HandleGetTenant",
	})
	l.Debug("start")
	defer l.Debug("end")
	vars := mux.Vars(r)
	tenant := vars["tenant"]
	t := &Tenant{Name: tenant}
	if err := t.GetByName(); err != nil && err != gorm.ErrRecordNotFound {
		l.Error("error getting tenant: ", err)
		http.Error(w, "error getting tenant", http.StatusInternalServerError)
		return
	} else if err == gorm.ErrRecordNotFound {
		l.WithField("tenant", tenant).Debug("tenant not found")
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	r.Header.Set(utils.HeaderPrefix()+"tenant", tenant)
	if !auth.RequestAuthorized(r) {
		l.Debug("unauthorized")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if t.AccessPlanID == 0 {
		l.WithField("tenant", t).Debug("tenant has no access plan")
		http.Error(w, "tenant has no access plan", http.StatusNotFound)
		return
	}
	l.WithField("tenant", t).Debug("tenant found")
	r.Header.Set("Content-Type", "application/json")
	redirect := r.URL.Query().Get("redirect")
	if redirect != "" {
		l.WithField("redirect", redirect).Debug("redirecting")
		http.Redirect(w, r, redirect, http.StatusFound)
	}
	if jerr := json.NewEncoder(w).Encode(t); jerr != nil {
		l.Error("error encoding tenant: ", jerr)
		http.Error(w, "error encoding tenant", http.StatusInternalServerError)
	}
}

func (t *Tenant) PaymentRequest(ap *AccessPlan) (string, error) {
	l := log.WithFields(log.Fields{
		"package":    "tenant",
		"action":     "Tenant.PaymentRequest",
		"name":       t.Name,
		"accessPlan": ap,
	})
	l.Debug("start")
	defer l.Debug("end")
	if t.Name == "" {
		l.Error("name is empty")
		return "", errors.New("name is empty")
	}
	req := &hpay.Meta{
		Claims: jwt.MapClaims{
			"sub": t.Name,
			"pid": ap.Name,
			"iss": os.Getenv("JWT_ISS"),
		},
		Renewable: true,
		Payment: &payment.Payment{
			Tenant: t.Name,
		},
	}
	if ap.Expiry > 0 {
		req.Exp = time.Duration(ap.Expiry)
	}
	for _, r := range ap.AccessPlanAmounts {
		req.Payment.Requests = append(req.Payment.Requests, &payment.PaymentRequest{
			Network: r.Network,
			Amount:  r.Amount,
		})
	}
	jd, err := json.Marshal(req)
	if err != nil {
		l.Error("error marshalling payment request: ", err)
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(jd)
	return b64, nil
}

func HandleHeadPaymentRequest(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"package": "tenant",
		"action":  "HandleHeadPaymentRequest",
	})
	l.Debug("start")
	defer l.Debug("end")
	vars := mux.Vars(r)
	tenant := vars["tenant"]
	if tenant == "" {
		l.Error("tenant is empty")
		http.Error(w, "tenant is empty", http.StatusBadRequest)
		return
	}
	tenant = utils.TenantName(tenant)
	if tenant == os.Getenv("DEFAULT_TENANT") || tenant == os.Getenv("ROOT_TENANT") || tenant == "402" {
		l.Error("tenant is not allowed")
		http.Error(w, "tenant is not allowed", http.StatusBadRequest)
		return
	}
	plan := vars["plan"]
	if plan == "" {
		l.Info("plan is empty, using default")
		plan = os.Getenv("DEFAULT_PLAN_NAME")
	}
	ap := &AccessPlan{Name: plan}
	if err := ap.GetByName(); err != nil {
		l.Error("error getting access plan: ", err)
		http.Error(w, "error getting access plan", http.StatusInternalServerError)
		return
	}
	t := &Tenant{Name: tenant}
	if err := t.GetByName(); err != nil && err != gorm.ErrRecordNotFound {
		l.Error("error getting tenant: ", err)
		http.Error(w, "error getting tenant", http.StatusInternalServerError)
		return
	}
	r.Header.Set(utils.HeaderPrefix()+"tenant", tenant)
	l.WithField("tenant", t).Debug("tenant found")
	if t.ID != 0 && !auth.RequestAuthorized(r) {
		l.Debug("unauthorized")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	req, err := t.PaymentRequest(ap)
	if err != nil {
		l.Error("error getting payment request: ", err)
		http.Error(w, "error getting payment request", http.StatusInternalServerError)
		return
	}
	w.Header().Set(utils.HeaderPrefix()+"request", req)
	w.Header().Set(utils.HeaderPrefix()+"required", "true")
	w.Header().Set(utils.HeaderPrefix()+"cache", "false")
	w.WriteHeader(http.StatusPaymentRequired)
}

func HandleGenerateNewJWT(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"package": "tenant",
		"action":  "HandleGenerateNewJWT",
	})
	l.Debug("start")
	defer l.Debug("end")
	vars := mux.Vars(r)
	tenant := vars["tenant"]
	if tenant == "" {
		l.Error("tenant is empty")
		http.Error(w, "tenant is empty", http.StatusBadRequest)
		return
	}
	r.Header.Set(utils.HeaderPrefix()+"tenant", tenant)
	if !auth.RequestAuthorized(r) {
		l.Debug("unauthorized")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	t := &Tenant{Name: tenant}
	if err := t.GetByName(); err != nil && err != gorm.ErrRecordNotFound {
		l.Error("error getting tenant: ", err)
		http.Error(w, "error getting tenant", http.StatusInternalServerError)
		return
	} else if err == gorm.ErrRecordNotFound {
		l.WithField("tenant", tenant).Debug("tenant not found")
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	l.WithField("tenant", t).Debug("tenant found")
	var exp time.Time
	expStr := r.URL.Query().Get("exp")
	if expStr != "" {
		expDur, err := time.ParseDuration(expStr)
		if err != nil {
			l.Error("error converting exp: ", err)
			http.Error(w, "error converting exp", http.StatusBadRequest)
			return
		}
		exp = time.Now().Add(expDur)
	}

	claims := jwt.MapClaims{
		"iss": os.Getenv("JWT_ISS"),
		"tid": t.Name,
	}
	jwt, err := auth.GenerateJWT(claims, exp, utils.TokenKeyID())
	if err != nil {
		l.Error("error generating JWT: ", err)
		http.Error(w, "error generating JWT", http.StatusInternalServerError)
		return
	}
	var res struct {
		Token string `json:"token"`
	}
	res.Token = jwt
	if jerr := json.NewEncoder(w).Encode(res); jerr != nil {
		l.Error("error encoding JWT: ", jerr)
		http.Error(w, "error encoding JWT", http.StatusInternalServerError)
	}
}
