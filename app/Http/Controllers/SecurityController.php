<?php

namespace App\Http\Controllers;

use App\Models\Machine;
use App\Models\Workspace;
use App\Support\Machines\MachinePolicies;
use App\Support\Security\Posture;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

class SecurityController extends Controller
{
    public function index(Workspace $workspace): Response
    {
        Gate::authorize('manageMachines', $workspace);

        $ruled = MachinePolicies::ruled($workspace->id);
        $default = MachinePolicies::defaultFor($workspace);
        $machines = $workspace->machines()->whereNotNull('uid')->with(['policy', 'group.policy'])->orderBy('name')->get();

        $rows = $machines->map(function (Machine $machine) use ($ruled, $default) {
            $policy = MachinePolicies::resolve($machine, $ruled, $default)['policy'];

            return [
                'id' => $machine->id,
                'name' => $machine->name,
                'online' => $machine->isOnline(),
                'policy' => $policy->name,
                ...Posture::report($machine, $policy),
            ];
        });

        $scored = $rows->whereNotNull('score');

        return Inertia::render('workspace/Security', [
            'workspace' => $workspace->toPageProps(),
            'machines' => $rows->values()->all(),
            'summary' => [
                'machines' => $rows->count(),
                'scored' => $scored->count(),
                'average' => $scored->isEmpty() ? null : (int) round($scored->avg('score')),
                'serious' => $rows->filter(fn (array $m) => collect($m['checks'])->contains(fn (array $c) => Posture::serious($c)))->count(),
            ],
        ]);
    }
}
