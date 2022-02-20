package tenant

import (
	"encoding/json"
	"net/http"

	"github.com/robertlestak/402/internal/db"
	"github.com/robertlestak/402/internal/utils"
	"github.com/robertlestak/402/pkg/auth"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type AccessPlanAmount struct {
	gorm.Model
	AccessPlanID uint
	Amount       float64 `json:"amount"`
	Network      string  `json:"network"`
}

type AccessPlan struct {
	gorm.Model
	Name              string              `gorm:"unique_index" json:"name"`
	Description       string              `json:"description"`
	Expiry            int                 `json:"expiry"`
	RequestsPerMinute int                 `json:"requests_per_minute"`
	RequestsPerDay    int                 `json:"requests_per_day"`
	AccessPlanAmounts []*AccessPlanAmount `json:"amount"`
}

func ListAccessPlans(page, pageSize int) ([]*AccessPlan, error) {
	var plans []*AccessPlan
	err := db.DB.Scopes(db.Paginate(page, pageSize)).Preload("AccessPlanAmounts").Find(&plans).Error
	if err != nil {
		return nil, err
	}
	return plans, err
}

func HandleListAccessPlans(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"package": "tenant",
		"action":  "HandleListAccessPlans",
	})
	l.Debug("start")
	defer r.Body.Close()
	page, pageSize := utils.GetPage(r)
	plans, err := ListAccessPlans(page, pageSize)
	if err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if jerr := json.NewEncoder(w).Encode(plans); jerr != nil {
		l.Error(jerr)
		http.Error(w, jerr.Error(), http.StatusInternalServerError)
		return
	}
	l.Debug("end")
}

func (a *AccessPlan) Create() error {
	return db.DB.Create(a).Error
}

func (a *AccessPlan) Update() error {
	return db.DB.Where("name = ?", a.Name).Save(a).Error
}

func (a *AccessPlan) GetByName() error {
	return db.DB.Where("name = ?", a.Name).Preload("AccessPlanAmounts").First(a).Error
}

func HandleCreateAccessPlan(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"package": "tenant",
		"action":  "HandleCreateAccessPlan",
	})
	l.Debug("start")
	defer r.Body.Close()
	if !auth.RequestAuthorizedRoot(r) {
		l.Debug("unauthorized")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	plan := &AccessPlan{}
	if err := json.NewDecoder(r.Body).Decode(&plan); err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := db.DB.Model(plan).Preload("AccessPlanAmounts").Where("name = ?", plan.Name).First(plan).Error; err != nil && err != gorm.ErrRecordNotFound {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if plan.Name != "" {
		l.Debug("plan exists")
		if cerr := plan.Update(); cerr != nil {
			l.Errorf("Update: %v", cerr)
			http.Error(w, cerr.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if cerr := plan.Create(); cerr != nil {
			l.Errorf("Create: %v", cerr)
			http.Error(w, cerr.Error(), http.StatusInternalServerError)
			return
		}
	}
	if jerr := json.NewEncoder(w).Encode(plan); jerr != nil {
		l.Error(jerr)
		http.Error(w, jerr.Error(), http.StatusInternalServerError)
		return
	}
	l.Debug("end")
}

func HandleDeleteAccessPlan(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"package": "tenant",
		"action":  "HandleDeleteAccessPlan",
	})
	defer r.Body.Close()
	l.Debug("start")
	if !auth.RequestAuthorizedRoot(r) {
		l.Debug("unauthorized")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	plan := &AccessPlan{}
	if err := json.NewDecoder(r.Body).Decode(&plan); err != nil {
		l.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res := db.DB.Delete(plan)
	if res.Error != nil {
		l.Errorf("Update: %v", res.Error)
		http.Error(w, res.Error.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	l.Debug("end")
}
