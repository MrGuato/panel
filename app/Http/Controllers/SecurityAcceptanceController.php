<?php

namespace App\Http\Controllers;

use App\Models\Activity;
use App\Models\Machine;
use App\Models\MachineSecurityAcceptance;
use App\Models\Workspace;
use App\Support\Audit\AuditContext;
use App\Support\Audit\Audited;
use App\Support\Security\Posture;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

class SecurityAcceptanceController extends Controller
{
    #[Audited]
    public function store(Request $request, Workspace $workspace, Machine $machine): RedirectResponse
    {
        abort_unless($machine->workspace_id === $workspace->id, 404);
        Gate::authorize('manageMachines', $workspace);

        $data = $request->validate([
            'check' => ['required', 'string', 'max:40'],
            'reason' => ['required', 'string', 'max:300'],
            'days' => ['required', 'integer', Rule::in(MachineSecurityAcceptance::DAYS)],
        ]);

        $check = collect(Posture::report($machine)['checks'])->firstWhere('key', $data['check']);
        if ($check === null || ! in_array($check['status'], ['fail', 'accepted'], true)) {
            throw ValidationException::withMessages(['check' => __('That check isn’t failing.')]);
        }
        if ($check['severity'] === 'critical') {
            throw ValidationException::withMessages(['check' => __('Critical checks can’t be accepted. Fix them instead.')]);
        }

        $machine->securityAcceptances()->updateOrCreate(['check' => $data['check']], [
            'fingerprint' => Posture::fingerprint($check),
            'reason' => $data['reason'],
            'user_id' => $request->user()->id,
            'expires_at' => now()->addDays((int) $data['days']),
        ]);
        Activity::record($workspace, 'security.accept', $machine->name, $machine, meta: ['check' => $data['check'], 'reason' => $data['reason'], 'days' => (int) $data['days']]);

        return back();
    }

    #[Audited]
    public function destroy(Workspace $workspace, Machine $machine, string $check): RedirectResponse
    {
        abort_unless($machine->workspace_id === $workspace->id, 404);
        Gate::authorize('manageMachines', $workspace);

        if ($machine->securityAcceptances()->where('check', $check)->delete() > 0) {
            Activity::record($workspace, 'security.unaccept', $machine->name, $machine, meta: ['check' => $check]);
        } else {
            AuditContext::nothingChanged();
        }

        return back();
    }
}
