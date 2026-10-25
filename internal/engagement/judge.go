package engagement

import (
	"fmt"
	"strings"
	"time"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/collector/workspace"
	"github.com/b87/scheck/internal/engagement/rules"
	"github.com/b87/scheck/internal/finding"
)

// judge is every network collector's verdicts over what this session's
// Recon holds, by the asset whose evidence each judged. No collector judges
// in Recon, and a resume judges again from the evidence; every web root is
// judged once all are read, so inherited mail policy can use another
// root's evidence whatever the order (docs/spec/runs.md, "Verdicts are not
// evidence"; docs/spec/web-collector.md, "Email").
func (r *run) judge() map[string][]finding.Judgment {
	out := map[string][]finding.Judgment{}
	for _, ra := range r.recon.Assets {
		a, ok := r.asset(ra.Name)
		if !ok {
			continue
		}
		switch {
		case ra.Web != nil:
			out[ra.ID] = web.Judge(r.webInput(a, *ra.Web))
		case ra.GitHub != nil:
			out[ra.ID] = githubc.Judge(*ra.GitHub, r.githubContext(a))
		case ra.Workspace != nil:
			out[ra.ID] = workspace.Judge(*ra.Workspace, a.ID, r.workspaceView(a))
		}
	}
	return out
}

// hostRules are the multi-fact rules' verdicts over each collected host's
// facts and its declared expected services, with the coverage they are
// marked against, by asset id (docs/spec/engagement.md, "Multi-fact
// rules"). A kept host is judged again from its kept facts.
func (r *run) hostRules() map[string]rules.Result {
	var hosts []rules.Host
	for _, ra := range r.recon.Assets {
		c, collected := r.hosts[ra.Name]
		a, ok := r.asset(ra.Name)
		if !collected || !ok {
			continue
		}
		h := rules.Host{Asset: ra.ID, Name: ra.Name, Facts: c.Facts()}
		if run := c.Evidence().Run; !run.Started.IsZero() {
			h.Collected = []time.Time{run.Started, run.Started.Add(time.Duration(run.DurationMS) * time.Millisecond)}
		}
		if a.Context != nil {
			h.Context.Exposure = a.Context.Exposure
			for i, s := range a.Context.ExpectedServices {
				h.Context.Services = append(h.Context.Services, rules.Service{Port: s.Port, Proto: strings.ToLower(s.Proto),
					Audience: s.Audience, Purpose: s.Purpose, Key: fmt.Sprintf("assets.%s.context.expected_services[%d]", a.Name, i)})
			}
		}
		hosts = append(hosts, h)
	}
	return rules.Judge(hosts)
}
