package streamwindow

import (
	"fmt"
	"time"
)

// Policy controls when org_admin users may start viewing client screens.
type Policy struct {
	Enabled   bool   `json:"enabled"`
	Timezone  string `json:"timezone"`
	StartHour int    `json:"startHour"`
	EndHour   int    `json:"endHour"`
}

func DefaultPolicy() Policy {
	return Policy{
		Enabled:   true,
		Timezone:  "Asia/Kathmandu",
		StartHour: 7,
		EndHour:   15,
	}
}

func (p Policy) Normalize() Policy {
	out := p
	if out.Timezone == "" {
		out.Timezone = DefaultPolicy().Timezone
	}
	if out.StartHour < 0 || out.StartHour > 23 {
		out.StartHour = DefaultPolicy().StartHour
	}
	if out.EndHour < 1 || out.EndHour > 24 {
		out.EndHour = DefaultPolicy().EndHour
	}
	if out.EndHour <= out.StartHour {
		out.StartHour = DefaultPolicy().StartHour
		out.EndHour = DefaultPolicy().EndHour
	}
	return out
}

func (p Policy) Location() (*time.Location, error) {
	return time.LoadLocation(p.Normalize().Timezone)
}

// AllowedNow reports whether streaming may start at now (in the policy timezone).
// Window is [startHour:00, endHour:00) — e.g. 7–15 allows 07:00 through 14:59:59.
func (p Policy) AllowedNow(now time.Time) (bool, error) {
	n := p.Normalize()
	if !n.Enabled {
		return true, nil
	}
	loc, err := n.Location()
	if err != nil {
		return false, err
	}
	t := now.In(loc)
	mins := t.Hour()*60 + t.Minute()
	start := n.StartHour * 60
	end := n.EndHour * 60
	return mins >= start && mins < end, nil
}

func (p Policy) HumanWindow() string {
	n := p.Normalize()
	return fmt.Sprintf("%02d:00–%02d:00", n.StartHour, n.EndHour)
}

func (p Policy) DenyMessage() string {
	n := p.Normalize()
	return fmt.Sprintf(
		"Screen viewing for team leads is only available %s Nepal time (%s), daily.",
		n.HumanWindow(),
		n.Timezone,
	)
}
