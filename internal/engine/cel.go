package engine

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/vakta-project/vakta/internal/normalizer"
)

// NewCELEnv builds the CEL environment with the variables vakta rules use:
// event, detail, host. Detail is exposed as a map<string, dyn>. Exported so
// the playbook engine reuses the same activation shape for step conditions.
func NewCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("detail", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("host", cel.MapType(cel.StringType, cel.DynType)),
	)
}

// CELCompile compiles a CEL expression against env and returns a runnable program.
// Exported for the playbook engine to pre-compile step conditions at action load.
func CELCompile(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("CEL compile: %w", iss.Err())
	}
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("CEL program: %w", err)
	}
	return prg, nil
}

// ActivationFor builds the {event, detail, host} map a CEL program receives.
// Exported so the playbook engine evaluates step conditions against the same
// schema rules use.
func ActivationFor(ev normalizer.Event) map[string]any {
	return activationFor(ev)
}

// activationFor builds the {event, detail, host} map for evaluation.
func activationFor(ev normalizer.Event) map[string]any {
	return map[string]any{
		"event": map[string]any{
			"type":      ev.Type,
			"source":    int(ev.Source),
			"pid":       int(ev.PID),
			"ppid":      int(ev.PPID),
			"uid":       int(ev.UID),
			"comm":      ev.Comm,
			"ret":       ev.Ret,
			"cgroup_id": int(ev.CgroupID),
		},
		"detail": detailMap(ev.Detail),
		"host":   map[string]any{"name": ev.Host},
	}
}

// detailMap projects a typed Detail into a snake_case map for CEL access.
// Returns an empty map if Detail is nil so rules can safely reference detail.*.
func detailMap(d any) map[string]any {
	switch v := d.(type) {
	case *normalizer.ExecDetail:
		return map[string]any{"filename": v.Filename, "argv": stringArray(v.Argv)}
	case *normalizer.ConnectDetail:
		return map[string]any{
			"dst_ip": v.DstIP.String(), "dst_port": int(v.DstPort),
			"family": int(v.Family), "errno": int(v.Errno),
		}
	case *normalizer.OpenDetail:
		return map[string]any{"path": v.Path, "flags": int(v.Flags)}
	case *normalizer.CloneDetail:
		return map[string]any{"clone_flags": int(v.CloneFlags)}
	case *normalizer.UnshareDetail:
		return map[string]any{"unshare_flags": int(v.UnshareFlags)}
	case *normalizer.PtraceDetail:
		return map[string]any{"request": v.Request, "target_pid": int(v.TargetPID)}
	case *normalizer.ModuleDetail:
		return map[string]any{"name": v.Name}
	case *normalizer.BPFLoadDetail:
		return map[string]any{"prog_type": int(v.ProgType)}
	case *normalizer.MemfdDetail:
		return map[string]any{"name": v.Name, "flags": int(v.Flags)}
	case *normalizer.ChmodDetail:
		return map[string]any{
			"path": v.Path, "mode": int(v.Mode),
			"suid": v.SUID, "sgid": v.SGID,
		}
	case *normalizer.MmapExecDetail:
		return map[string]any{"addr": int(v.Addr), "len": int(v.Len), "prot": int(v.Prot)}
	case *normalizer.ProcProbeDetail:
		return map[string]any{"target_pid": int(v.TargetPID)}
	case *normalizer.AuditFIMDetail:
		return map[string]any{"path": v.Path, "audit_key": v.AuditKey, "op": v.Op}
	case *normalizer.K8sDetail:
		return map[string]any{
			"verb": v.Verb, "resource": v.Resource, "namespace": v.Namespace,
			"name": v.Name, "username": v.Username, "source_ip": v.SourceIP,
		}
	default:
		return map[string]any{}
	}
}

func stringArray(xs []string) ref.Val {
	conv := make([]any, len(xs))
	for i, s := range xs {
		conv[i] = s
	}
	return types.DefaultTypeAdapter.NativeToValue(conv)
}
