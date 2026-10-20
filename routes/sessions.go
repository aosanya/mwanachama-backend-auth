package routes

import (
	"errors"
	"net/http"
	"time"

	"github.com/aosanya/mwanachama-backend-shared/httpwire"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

type CurrentSession interface {
	CallerSessionID(r *http.Request) string
}

type sessionView struct {
	mwanachamaauth.SessionRecord
	Current bool `json:"current"`
}

const sessionsNotKept = "this mount keeps no sessions"

func callerOf(identity Identity, r *http.Request) string {
	if identity == nil {
		return ""
	}
	return identity.CallerID(r)
}

func currentOf(current CurrentSession, r *http.Request) string {
	if current == nil {
		return ""
	}
	return current.CallerSessionID(r)
}

func ListOwnSessions(sessions mwanachamaauth.SessionRepository, identity Identity, current CurrentSession) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sessions == nil {
			httpwire.WriteErr(w, http.StatusNotImplemented, sessionsNotKept)
			return
		}
		caller := callerOf(identity, r)
		if caller == "" {
			httpwire.WriteErr(w, http.StatusUnauthorized, "a signed-in caller is required")
			return
		}
		list, err := sessions.ListLive(r.Context(), caller, time.Now().UTC())
		if err != nil {
			httpwire.WriteErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		inUse := currentOf(current, r)
		out := make([]sessionView, 0, len(list))
		for _, s := range list {
			out = append(out, sessionView{SessionRecord: s, Current: inUse != "" && s.ID == inUse})
		}
		httpwire.WriteJSON(w, http.StatusOK, map[string]any{"sessions": out})
	}
}

func EndOwnSession(sessions mwanachamaauth.SessionRepository, identity Identity, current CurrentSession) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sessions == nil {
			httpwire.WriteErr(w, http.StatusNotImplemented, sessionsNotKept)
			return
		}
		caller := callerOf(identity, r)
		if caller == "" {
			httpwire.WriteErr(w, http.StatusUnauthorized, "a signed-in caller is required")
			return
		}
		id := r.PathValue("sessionID")
		if inUse := currentOf(current, r); inUse != "" && id == inUse {
			httpwire.WriteErr(w, http.StatusConflict, mwanachamaauth.ErrSessionInUse.Error())
			return
		}
		err := sessions.End(r.Context(), caller, id, time.Now().UTC())
		if errors.Is(err, mwanachamaauth.ErrSessionNotFound) {
			httpwire.WriteErr(w, http.StatusNotFound, err.Error())
			return
		}
		if err != nil {
			httpwire.WriteErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
