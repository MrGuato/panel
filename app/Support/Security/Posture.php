<?php

namespace App\Support\Security;

use App\Models\DaemonRelease;
use App\Models\Machine;
use App\Models\MachinePolicy;
use App\Models\MachineSecurityAcceptance;
use App\Models\MachineVulnerability;
use App\Support\DaemonUpdates;
use App\Support\Firewall;
use App\Support\Machines\MachinePolicies;

/**
 * @phpstan-type Check array{key: string, severity: string, status: string, params: array<string, string|int>, accepted?: array{by: string|null, reason: string, until: string}}
 * @phpstan-type Report array{state: string, score: int|null, grade: string|null, seenAt: string|null, checks: list<Check>}
 */
class Posture
{
    public const WEIGHTS = ['critical' => 10, 'high' => 5, 'medium' => 2, 'low' => 1];

    public const CLEARTEXT_PORTS = [21 => 'FTP', 23 => 'Telnet', 512 => 'rexec', 513 => 'rlogin', 514 => 'rsh'];

    public const FAILED_SIGN_INS = 20;

    public const STALE_AFTER_HOURS = 24;

    public const CERTIFICATE_DAYS = 14;

    public const WEB_PORTS = [80, 443];

    public const PANEL_IMAGE = 'ghcr.io/serveroshq/';

    public const FINGERPRINT = ['ports', 'services', 'names', 'cves', 'latest'];

    /** @return Report */
    public static function report(Machine $machine, ?MachinePolicy $policy = null): array
    {
        $watching = ($policy ?? MachinePolicies::for($machine))->security_watch;
        $facts = $watching ? SecurityFacts::of($machine) : new SecurityFacts;
        $view = Firewall::view($machine);

        $checks = [
            self::sshPassword($facts),
            self::sshRoot($facts),
            self::signIns($facts),
            self::passwordUsed($facts),
            self::exposed($machine, $view),
            self::cleartext($view),
            self::dockerPorts($machine, $view),
            self::firewall($machine),
            self::firewallDefault($machine),
            ...self::certificates($machine),
            self::securityUpdates($machine),
            ...self::vulnerabilities($machine),
            self::autoUpdates($facts),
            self::reboot($machine),
            self::daemon($machine),
        ];
        $checks = self::accepted($machine, $checks);
        usort($checks, fn (array $a, array $b) => [self::rank($a['status']), -self::WEIGHTS[$a['severity']]]
            <=> [self::rank($b['status']), -self::WEIGHTS[$b['severity']]]);

        $state = self::state($machine, $checks, $watching);
        $score = $state === 'scored' ? self::score($checks) : null;

        return [
            'state' => $state,
            'score' => $score,
            'grade' => $score === null ? null : self::grade($score),
            'seenAt' => $machine->last_seen_at?->toIso8601String(),
            'checks' => $checks,
        ];
    }

    /** @param list<Check> $checks */
    public static function score(array $checks): int
    {
        $possible = $lost = 0;
        foreach ($checks as $check) {
            if (in_array($check['status'], ['unknown', 'accepted'], true)) {
                continue;
            }
            $possible += self::WEIGHTS[$check['severity']];
            $lost += $check['status'] === 'fail' ? self::WEIGHTS[$check['severity']] : 0;
        }

        return $possible === 0 ? 0 : (int) round(100 * ($possible - $lost) / $possible);
    }

    public static function grade(int $score): string
    {
        return match (true) {
            $score >= 90 => 'A',
            $score >= 80 => 'B',
            $score >= 70 => 'C',
            $score >= 60 => 'D',
            default => 'F',
        };
    }

    /** @param Check $check */
    public static function serious(array $check): bool
    {
        return $check['status'] === 'fail' && self::WEIGHTS[$check['severity']] >= self::WEIGHTS['high'];
    }

    /** @param Check $check */
    public static function fingerprint(array $check): string
    {
        return sha1((string) json_encode(array_intersect_key($check['params'], array_flip(self::FINGERPRINT))));
    }

    /**
     * @param  list<Check>  $checks
     * @return list<Check>
     */
    private static function accepted(Machine $machine, array $checks): array
    {
        $machine->loadMissing('securityAcceptances.user');
        $accepted = $machine->securityAcceptances->filter(fn (MachineSecurityAcceptance $a) => $a->expires_at->isFuture())->keyBy('check');

        return array_map(function (array $check) use ($accepted) {
            $acceptance = $accepted->get($check['key']);
            if ($acceptance === null || $check['status'] !== 'fail' || $check['severity'] === 'critical' || $acceptance->fingerprint !== self::fingerprint($check)) {
                return $check;
            }

            return [...$check, 'status' => 'accepted', 'accepted' => [
                'by' => $acceptance->user?->name,
                'reason' => $acceptance->reason,
                'until' => $acceptance->expires_at->toIso8601String(),
            ]];
        }, $checks);
    }

    /** @param list<Check> $checks */
    private static function state(Machine $machine, array $checks, bool $watching): string
    {
        $known = array_filter($checks, fn (array $c) => $c['status'] !== 'unknown');

        return match (true) {
            $known === [] => 'waiting',
            $machine->last_seen_at === null || $machine->last_seen_at->lt(now()->subHours(self::STALE_AFTER_HOURS)) => 'stale',
            ! $watching => 'watch_off',
            collect($checks)->contains(fn (array $c) => $c['status'] === 'unknown' && self::WEIGHTS[$c['severity']] >= self::WEIGHTS['high']) => 'incomplete',
            default => 'scored',
        };
    }

    /** @return Check */
    private static function sshPassword(SecurityFacts $facts): array
    {
        $password = $facts->passwordSignIn();

        return self::check('ssh_password', 'medium', $password === null ? null : ! $password);
    }

    /** @return Check */
    private static function sshRoot(SecurityFacts $facts): array
    {
        if ($facts->permitRootLogin === null) {
            return self::check('ssh_root', 'high', null);
        }

        return self::check('ssh_root', 'high', $facts->permitRootLogin !== 'yes' || $facts->passwordSignIn() === false);
    }

    /** @return Check */
    private static function signIns(SecurityFacts $facts): array
    {
        if ($facts->failedSignIns === null) {
            return self::check('sign_ins', 'medium', null);
        }

        return self::check('sign_ins', 'medium', $facts->failedSignIns < self::FAILED_SIGN_INS || $facts->passwordSignIn() === false, [
            'failed' => $facts->failedSignIns,
            'sources' => $facts->failedSources,
            'root' => $facts->failedAsRoot,
            'minutes' => $facts->windowMinutes,
        ]);
    }

    /** @return Check */
    private static function passwordUsed(SecurityFacts $facts): array
    {
        if ($facts->passwordSignIns === null) {
            return self::check('password_used', 'medium', null);
        }

        return self::check('password_used', 'medium', $facts->passwordSignIns === 0, [
            'count' => $facts->passwordSignIns,
            'minutes' => $facts->windowMinutes,
        ]);
    }

    /**
     * @param  array{active: bool, ports: list<array{port: int, proto: string, process: string|null, exposure: string|null, because: string|null, what: string|null, ssh: bool}>}|null  $view
     * @return Check
     */
    private static function dockerPorts(Machine $machine, ?array $view): array
    {
        if ($view === null || ! $view['active']) {
            return self::check('docker_ports', 'medium', null);
        }
        $panel = [];
        foreach ($machine->inventory['services'] ?? [] as $service) {
            if (is_array($service) && str_starts_with((string) ($service['details']['image'] ?? ''), self::PANEL_IMAGE)) {
                $panel = [...$panel, ...array_filter((array) ($service['ports'] ?? []), 'is_int')];
            }
        }
        $ports = [];
        foreach ($view['ports'] as $port) {
            if ($port['exposure'] === 'docker' && $port['what'] === null
                && ! in_array($port['port'], self::WEB_PORTS, true) && ! in_array($port['port'], $panel, true)) {
                $ports[] = "{$port['port']}/{$port['proto']}";
            }
        }

        return self::check('docker_ports', 'medium', $ports === [], ['ports' => implode(', ', $ports)]);
    }

    /** @return Check */
    private static function firewallDefault(Machine $machine): array
    {
        $report = Firewall::report($machine);
        $incoming = $report['default_incoming'] ?? null;
        if (($report['active'] ?? false) !== true || ! is_string($incoming)) {
            return self::check('firewall_default', 'medium', null);
        }

        return self::check('firewall_default', 'medium', strtolower($incoming) !== 'allow');
    }

    /** @return list<Check> */
    private static function certificates(Machine $machine): array
    {
        if ($machine->inventory === null) {
            return [self::check('certificate_expired', 'high', null), self::check('certificate_expiring', 'medium', null)];
        }

        $latest = [];
        foreach ($machine->inventory['certificates'] ?? [] as $certificate) {
            if (! is_array($certificate) || ! is_int($certificate['not_after'] ?? null)) {
                continue;
            }
            $names = array_filter((array) ($certificate['names'] ?? []), 'is_string') ?: [(string) ($certificate['subject'] ?? $certificate['path'] ?? '')];
            foreach ($names as $name) {
                $latest[$name] = max($latest[$name] ?? 0, $certificate['not_after']);
            }
        }
        $expired = array_keys(array_filter($latest, fn (int $until) => $until < now()->getTimestamp()));
        $expiring = array_keys(array_filter($latest, fn (int $until) => $until >= now()->getTimestamp() && $until < now()->addDays(self::CERTIFICATE_DAYS)->getTimestamp()));

        return [
            self::check('certificate_expired', 'high', $expired === [], ['names' => implode(', ', $expired)]),
            self::check('certificate_expiring', 'medium', $expiring === [], ['names' => implode(', ', $expiring), 'days' => self::CERTIFICATE_DAYS]),
        ];
    }

    /** @return list<Check> */
    private static function vulnerabilities(Machine $machine): array
    {
        if (! config('security.cves.enabled')) {
            return [];
        }
        if ($machine->vulns_scanned_at === null) {
            return [self::check('exploited', 'critical', null), self::check('cves', 'high', null)];
        }

        $machine->loadMissing(['vulnerabilities' => fn ($query) => $query->open()->with('vulnerability')]);
        $open = $machine->vulnerabilities->whereNull('resolved_at');
        [$exploited, $rest] = $open->partition(fn (MachineVulnerability $found) => $found->vulnerability->exploited);
        $serious = $rest->filter(fn (MachineVulnerability $found) => in_array($found->vulnerability->severity, ['critical', 'high'], true));

        return [
            self::check('exploited', 'critical', $exploited->isEmpty(), self::cves($exploited->all())),
            self::check('cves', 'high', $serious->isEmpty(), self::cves($serious->all())),
        ];
    }

    /**
     * @param  array<int, MachineVulnerability>  $found
     * @return array{cves: string, more?: int}
     */
    private static function cves(array $found): array
    {
        $ids = array_values(array_unique(array_map(fn (MachineVulnerability $f) => $f->vulnerability->cve, $found)));

        $params = ['cves' => implode(', ', array_slice($ids, 0, 3))];

        return count($ids) > 3 ? [...$params, 'more' => count($ids) - 3] : $params;
    }

    /** @return Check */
    private static function daemon(Machine $machine): array
    {
        $arch = DaemonRelease::arch((string) ($machine->facts['arch'] ?? ''));
        $latest = $arch === null ? null : DaemonRelease::latest('stable', $arch);
        if ($machine->daemon_version === null || $latest === null) {
            return self::check('daemon', 'low', null);
        }

        return self::check('daemon', 'low', DaemonUpdates::available($machine) === null, [
            'installed' => $machine->daemon_version,
            'latest' => $latest->version,
        ]);
    }

    /**
     * @param  array{ports: list<array{port: int, proto: string, process: string|null, exposure: string|null, because: string|null, what: string|null, ssh: bool}>}|null  $view
     * @return Check
     */
    private static function exposed(Machine $machine, ?array $view): array
    {
        if ($view === null) {
            return self::check('exposed', 'high', null);
        }
        $exposed = array_map(fn (array $p) => "{$p['what']} ({$p['port']}/{$p['proto']})", Firewall::exposedDatabases($machine, $view));

        return self::check('exposed', 'high', $exposed === [], ['services' => implode(', ', $exposed)]);
    }

    /**
     * @param  array{ports: list<array{port: int, proto: string, process: string|null, exposure: string|null, because: string|null, what: string|null, ssh: bool}>}|null  $view
     * @return Check
     */
    private static function cleartext(?array $view): array
    {
        if ($view === null) {
            return self::check('cleartext', 'high', null);
        }

        $found = [];
        foreach ($view['ports'] as $port) {
            if ($port['proto'] === 'tcp' && isset(self::CLEARTEXT_PORTS[$port['port']]) && in_array($port['exposure'], Firewall::REACHABLE, true)) {
                $found[] = self::CLEARTEXT_PORTS[$port['port']]." ({$port['port']}/tcp)";
            }
        }

        return self::check('cleartext', 'high', $found === [], ['services' => implode(', ', $found)]);
    }

    /** @return Check */
    private static function firewall(Machine $machine): array
    {
        $active = Firewall::report($machine)['active'] ?? null;

        return self::check('firewall', 'low', is_bool($active) ? $active : null);
    }

    /** @return Check */
    private static function securityUpdates(Machine $machine): array
    {
        if ($machine->updates_checked_at === null) {
            return self::check('security_updates', 'medium', null);
        }
        $count = (int) $machine->security_updates_count;

        return self::check('security_updates', 'medium', $count === 0, ['count' => $count]);
    }

    /** @return Check */
    private static function autoUpdates(SecurityFacts $facts): array
    {
        return self::check('auto_updates', 'low', $facts->autoUpdates);
    }

    /** @return Check */
    private static function reboot(Machine $machine): array
    {
        if ($machine->updates_checked_at === null) {
            return self::check('reboot', 'low', null);
        }

        return self::check('reboot', 'low', ! $machine->reboot_required);
    }

    /**
     * @param  array<string, string|int>  $params
     * @return Check
     */
    private static function check(string $key, string $severity, ?bool $passed, array $params = []): array
    {
        return [
            'key' => $key,
            'severity' => $severity,
            'status' => match ($passed) {
                true => 'pass',
                false => 'fail',
                null => 'unknown',
            },
            'params' => $params,
        ];
    }

    private static function rank(string $status): int
    {
        return ['fail' => 0, 'accepted' => 1, 'unknown' => 2, 'pass' => 3][$status];
    }
}
