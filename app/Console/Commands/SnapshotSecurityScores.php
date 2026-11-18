<?php

namespace App\Console\Commands;

use App\Models\Machine;
use App\Models\MachinePolicy;
use App\Models\MachineSecurityScore;
use App\Support\Machines\MachinePolicies;
use App\Support\Security\Posture;
use Illuminate\Console\Command;
use Illuminate\Support\Collection;

class SnapshotSecurityScores extends Command
{
    protected $signature = 'security:snapshot';

    protected $description = 'Keep today’s security score for every machine, for the trend on the Security tab';

    public function handle(): int
    {
        $today = now()->toDateString();
        /** @var array<int, array{Collection<int, MachinePolicy>, MachinePolicy}> $policies */
        $policies = [];

        Machine::query()->whereNotNull('uid')
            ->with(['workspace', 'policy', 'group.policy', 'securityAcceptances.user', 'vulnerabilities' => fn ($query) => $query->open()->with('vulnerability')])
            ->chunkById(200, function ($machines) use ($today, &$policies) {
                foreach ($machines as $machine) {
                    [$ruled, $default] = $policies[$machine->workspace_id] ??= [MachinePolicies::ruled($machine->workspace_id), MachinePolicies::defaultFor($machine->workspace)];
                    $report = Posture::report($machine, MachinePolicies::resolve($machine, $ruled, $default)['policy']);
                    $row = MachineSecurityScore::query()->where('machine_id', $machine->id)->whereDate('date', $today)->first()
                        ?? new MachineSecurityScore(['machine_id' => $machine->id, 'date' => $today]);
                    $row->fill([
                        'state' => $report['state'],
                        'score' => $report['score'],
                        'failing' => collect($report['checks'])->where('status', 'fail')->pluck('key')->values()->all(),
                    ])->save();
                }
            });

        MachineSecurityScore::query()->whereDate('date', '<', now()->subDays(MachineSecurityScore::KEEP_DAYS)->toDateString())->delete();

        return self::SUCCESS;
    }
}
