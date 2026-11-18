<?php

namespace App\Http\Controllers;

use App\Models\Machine;
use App\Models\MachineSecurityScore;
use App\Models\Workspace;
use App\Support\Machines\MachinePolicies;
use App\Support\Security\Posture;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/** @phpstan-import-type Check from Posture */
class SecurityController extends Controller
{
    public const TREND_DAYS = 30;

    public function index(Workspace $workspace): Response
    {
        Gate::authorize('manageMachines', $workspace);

        $ruled = MachinePolicies::ruled($workspace->id);
        $default = MachinePolicies::defaultFor($workspace);
        $machines = $workspace->machines()->whereNotNull('uid')->with(['policy', 'group.policy', 'securityAcceptances.user', 'vulnerabilities' => fn ($query) => $query->open()->with('vulnerability')])->orderBy('name')->get();
        $history = MachineSecurityScore::query()
            ->whereIn('machine_id', $machines->modelKeys())
            ->whereDate('date', '>=', now()->subDays(self::TREND_DAYS - 1)->toDateString())
            ->get()
            ->groupBy('machine_id');

        $rows = $machines->map(function (Machine $machine) use ($ruled, $default, $history) {
            $policy = MachinePolicies::resolve($machine, $ruled, $default)['policy'];
            $report = Posture::report($machine, $policy);

            return [
                'id' => $machine->id,
                'name' => $machine->name,
                'online' => $machine->isOnline(),
                'policy' => $policy->name,
                ...$report,
                ...self::history($history->get($machine->id, collect()), $report),
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

    /**
     * @param  Collection<int, MachineSecurityScore>  $scores
     * @param  array{score: int|null, checks: list<Check>}  $report
     * @return array{trend: list<array{day: string, score: int|null}>, newFailing: list<string>}
     */
    private static function history(Collection $scores, array $report): array
    {
        $byDate = $scores->keyBy(fn (MachineSecurityScore $s) => $s->date->toDateString());

        $trend = [];
        for ($day = self::TREND_DAYS - 1; $day >= 0; $day--) {
            $date = now()->subDays($day)->toDateString();
            $trend[] = ['day' => $date, 'score' => $day === 0 ? $report['score'] : $byDate->get($date)?->score];
        }

        $yesterday = $byDate->get(now()->subDay()->toDateString());
        $failing = array_column(array_filter($report['checks'], fn (array $c) => $c['status'] === 'fail'), 'key');

        return [
            'trend' => $trend,
            'newFailing' => $yesterday === null ? [] : array_values(array_diff($failing, $yesterday->failing)),
        ];
    }
}
