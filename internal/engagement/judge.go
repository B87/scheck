package engagement

import (
	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/collector/workspace"
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
