<?php

use App\Models\DaemonRelease;
use App\Models\Machine;
use App\Models\MachineVulnerability;
use App\Models\User;
use App\Models\Vulnerability;
use App\Models\Workspace;
use App\Support\Health\WorkspaceHealth;
use App\Support\Machines\MachinePolicies;
use App\Support\Security\Posture;
use App\Support\Security\SecurityFacts;
use Illuminate\Support\Str;
use Inertia\Testing\AssertableInertia as Assert;

/**
 * @param  array<string, mixed>  $security
 * @param  list<array<string, mixed>>  $listeners
 * @param  array<string, mixed>  $firewall
 * @param  array<string, mixed>  $attributes
 */
function postureMachine(Workspace $workspace, string $name, array $security, array $listeners = [], array $firewall = ['backend' => 'ufw', 'installed' => true, 'active' => true, 'default_incoming' => 'deny', 'ports' => []], array $attributes = []): Machine
{
    $machine = Machine::factory()->for($workspace)->create(['name' => $name]);
    $machine->forceFill([
        'uid' => (string) Str::uuid(),
        'last_seen_at' => now(),
        'facts' => ['os' => 'ubuntu', 'os_version' => '24.04', 'security' => $security],
        'inventory' => ['scanned_at' => now()->getTimestamp(), 'complete' => true, 'listeners' => $listeners, 'services' => [], 'firewall' => $firewall],
        'updates_checked_at' => now(),
        'security_updates_count' => 0,
        'reboot_required' => false,
        'vulns_scanned_at' => now(),
        ...$attributes,
    ])->save();

    return $machine;
}

/** @return array<string, mixed> */
function hardened(): array
{
    return [
        'ssh' => ['password_authentication' => false, 'permit_root_login' => 'prohibit-password', 'ports' => [22]],
        'logins' => ['window_secs' => 3600, 'failed' => 2, 'sources' => 1, 'root' => 0, 'accepted_password' => 0],
        'auto_updates' => true,
    ];
}

function postureCve(Machine $machine, string $cve, string $severity, bool $exploited = false, bool $resolved = false): void
{
    $vulnerability = Vulnerability::query()->create(['cve' => $cve, 'severity' => $severity, 'exploited' => $exploited]);
    MachineVulnerability::query()->create([
        'machine_id' => $machine->id, 'vulnerability_id' => $vulnerability->id, 'source' => 'openssl', 'packages' => ['openssl'],
        'detected_at' => now(), 'resolved_at' => $resolved ? now() : null,
    ]);
}

/** @return array<string, array<string, mixed>> */
function postureChecks(array $report): array
{
    return collect($report['checks'])->keyBy('key')->all();
}

test('a hardened machine scores 100 and every check passes', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'web-1', hardened(), [
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 22, 'exe' => '/usr/sbin/sshd', 'pid' => 1],
        ['proto' => 'tcp', 'address' => '127.0.0.1', 'port' => 5432, 'exe' => '/usr/lib/postgresql/16/bin/postgres', 'pid' => 2],
    ]);

    $report = Posture::report($machine);

    expect($report['state'])->toBe('scored')
        ->and($report['score'])->toBe(100)
        ->and($report['grade'])->toBe('A')
        ->and(collect($report['checks'])->where('status', 'fail')->all())->toBe([]);
});

test('a machine failing every check scores 0, worst first, with the details to show', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'db-1', [
        'ssh' => ['password_authentication' => true, 'permit_root_login' => 'yes'],
        'logins' => ['window_secs' => 3600, 'failed' => 140, 'sources' => 9, 'root' => 60, 'accepted_password' => 3],
        'auto_updates' => false,
    ], [
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 5432, 'exe' => '/usr/lib/postgresql/16/bin/postgres', 'pid' => 2],
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 23, 'exe' => '/usr/sbin/in.telnetd', 'pid' => 3],
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 8080, 'exe' => '/usr/bin/docker-proxy', 'pid' => 4],
    ], ['backend' => 'ufw', 'installed' => true, 'active' => false, 'ports' => [
        ['port' => 5432, 'proto' => 'tcp', 'exposure' => 'open'],
        ['port' => 23, 'proto' => 'tcp', 'exposure' => 'open'],
        ['port' => 8080, 'proto' => 'tcp', 'exposure' => 'docker'],
    ]], ['security_updates_count' => 3, 'reboot_required' => true]);
    $machine->forceFill(['inventory' => [...$machine->inventory, 'certificates' => [
        ['path' => '/etc/ssl/a.pem', 'subject' => 'CN=a.example.com', 'issuer' => 'R11', 'not_after' => now()->subDay()->getTimestamp(), 'names' => ['a.example.com']],
        ['path' => '/etc/ssl/b.pem', 'subject' => 'CN=b.example.com', 'issuer' => 'R11', 'not_after' => now()->addDays(3)->getTimestamp(), 'names' => ['b.example.com']],
    ]]])->save();
    postureCve($machine, 'CVE-2026-0001', 'critical', exploited: true);
    postureCve($machine, 'CVE-2026-0002', 'high');

    $report = Posture::report($machine);
    $checks = postureChecks($report);

    expect($report['score'])->toBe(0)
        ->and($report['grade'])->toBe('F')
        ->and(collect($report['checks'])->pluck('status')->unique()->sort()->values()->all())->toBe(['fail', 'unknown'])
        ->and($report['checks'][0]['key'])->toBe('exploited')
        ->and($checks['exploited']['params'])->toBe(['cves' => 'CVE-2026-0001'])
        ->and($checks['cves']['params'])->toBe(['cves' => 'CVE-2026-0002'])
        ->and($checks['password_used']['params']['count'])->toBe(3)
        ->and($checks['certificate_expired']['params']['names'])->toBe('a.example.com')
        ->and($checks['certificate_expiring']['params']['names'])->toBe('b.example.com')
        ->and($checks['exposed']['params']['services'])->toBe('PostgreSQL (5432/tcp)')
        ->and($checks['cleartext']['params']['services'])->toBe('Telnet (23/tcp)')
        ->and($checks['sign_ins']['params'])->toMatchArray(['failed' => 140, 'sources' => 9, 'root' => 60, 'minutes' => 60])
        ->and($checks['security_updates']['params']['count'])->toBe(3);
});

test('the score is out of what was checked, so unknown checks cost nothing', function () {
    $check = fn (string $severity, string $status) => ['key' => 'x', 'severity' => $severity, 'status' => $status, 'params' => []];

    expect(Posture::score([$check('high', 'pass'), $check('medium', 'fail'), $check('low', 'pass'), $check('high', 'unknown')]))->toBe(75)
        ->and(Posture::score([$check('low', 'unknown')]))->toBe(0);
});

test('a machine missing a high-severity report is incomplete, not graded', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'new-1', ['ssh' => ['password_authentication' => false]]);

    $report = Posture::report($machine);

    expect($report['state'])->toBe('incomplete')
        ->and($report['score'])->toBeNull()
        ->and(postureChecks($report)['ssh_root']['status'])->toBe('unknown')
        ->and(postureChecks($report)['ssh_password']['status'])->toBe('pass');

    $nothing = Machine::factory()->for(Workspace::factory()->create())->create();
    $nothing->forceFill(['uid' => (string) Str::uuid(), 'facts' => null, 'inventory' => null])->save();
    expect(Posture::report($nothing)['state'])->toBe('waiting');
});

test('a machine that hasn’t reported for a day is stale, not graded', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'gone-1', hardened(), attributes: ['last_seen_at' => now()->subDays(2)]);

    $report = Posture::report($machine);

    expect($report['state'])->toBe('stale')
        ->and($report['score'])->toBeNull()
        ->and($report['grade'])->toBeNull();
});

test('values the daemon couldn’t read are unknown, not a pass', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'odd-1', [
        'ssh' => ['password_authentication' => null, 'permit_root_login' => null],
        'logins' => null,
        'auto_updates' => null,
    ]);

    $checks = postureChecks(Posture::report($machine));

    expect($checks['ssh_password']['status'])->toBe('unknown')
        ->and($checks['ssh_root']['status'])->toBe('unknown')
        ->and($checks['sign_ins']['status'])->toBe('unknown')
        ->and($checks['auto_updates']['status'])->toBe('unknown');
});

test('a cleartext service the firewall blocks doesn’t fail', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'ftp-1', hardened(), [
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 21, 'exe' => '/usr/sbin/vsftpd', 'pid' => 3],
    ], ['backend' => 'ufw', 'installed' => true, 'active' => true, 'ports' => [
        ['port' => 21, 'proto' => 'tcp', 'exposure' => 'blocked'],
    ]]);

    expect(postureChecks(Posture::report($machine))['cleartext']['status'])->toBe('pass');
});

test('root sign-in and failed sign-ins only fail when SSH accepts passwords', function () {
    $keysOnly = postureMachine(Workspace::factory()->create(), 'keys-1', [
        ...hardened(),
        'ssh' => ['password_authentication' => false, 'permit_root_login' => 'yes'],
        'logins' => ['window_secs' => 3600, 'failed' => 500, 'sources' => 40, 'root' => 300],
    ]);
    $passwords = postureMachine(Workspace::factory()->create(), 'pw-1', [
        ...hardened(),
        'ssh' => ['password_authentication' => true, 'permit_root_login' => 'yes'],
        'logins' => ['window_secs' => 3600, 'failed' => 500, 'sources' => 40, 'root' => 300],
    ]);

    expect(postureChecks(Posture::report($keysOnly))['ssh_root']['status'])->toBe('pass')
        ->and(postureChecks(Posture::report($keysOnly))['sign_ins']['status'])->toBe('pass')
        ->and(postureChecks(Posture::report($passwords))['ssh_root']['status'])->toBe('fail')
        ->and(postureChecks(Posture::report($passwords))['sign_ins']['status'])->toBe('fail');
});

test('a machine with security watch off says so instead of incomplete', function () {
    $workspace = Workspace::factory()->create();
    $machine = postureMachine($workspace, 'quiet-1', hardened());
    MachinePolicies::defaultFor($workspace)->update(['security_watch' => false]);

    $report = Posture::report($machine->fresh());

    expect($report['state'])->toBe('watch_off')
        ->and($report['score'])->toBeNull()
        ->and(postureChecks($report)['ssh_root']['status'])->toBe('unknown')
        ->and(postureChecks($report)['firewall']['status'])->toBe('pass');
});

test('the reader turns the daemon’s security report into typed values', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'typed-1', [
        'ssh' => ['password_authentication' => 'yes', 'permit_root_login' => 'Prohibit-Password'],
        'logins' => ['window_secs' => 1800, 'failed' => -3, 'sources' => 'many'],
        'auto_updates' => true,
    ]);

    $facts = SecurityFacts::of($machine);

    expect($facts->passwordAuthentication)->toBeNull()
        ->and($facts->permitRootLogin)->toBe('prohibit-password')
        ->and($facts->failedSignIns)->toBeNull()
        ->and($facts->failedSources)->toBe(0)
        ->and($facts->windowMinutes)->toBe(30)
        ->and($facts->autoUpdates)->toBeTrue();
});

test('an exposed database fails here exactly when the machine page warns about it', function () {
    $workspace = Workspace::factory()->create();
    $open = postureMachine($workspace, 'redis-1', hardened(), [
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 6379, 'exe' => '/usr/bin/redis-server', 'pid' => 4],
    ], ['backend' => 'ufw', 'installed' => true, 'active' => true, 'ports' => [['port' => 6379, 'proto' => 'tcp', 'exposure' => 'open']]]);
    $closed = postureMachine($workspace, 'redis-2', hardened(), [
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 6379, 'exe' => '/usr/bin/redis-server', 'pid' => 4],
    ], ['backend' => 'ufw', 'installed' => true, 'active' => true, 'ports' => [['port' => 6379, 'proto' => 'tcp', 'exposure' => 'blocked']]]);

    foreach ([$open, $closed] as $machine) {
        $warned = collect(app(WorkspaceHealth::class)->forMachine($machine))->contains(fn (array $i) => str_contains($i['id'], '-exposed-'));
        expect(postureChecks(Posture::report($machine))['exposed']['status'])->toBe($warned ? 'fail' : 'pass');
    }
    expect(postureChecks(Posture::report($open))['exposed']['status'])->toBe('fail');
});

test('the Security page lists the workspace’s machines, counting each serious one once', function () {
    $workspace = Workspace::factory()->create();
    postureMachine($workspace, 'web-1', hardened());
    postureMachine($workspace, 'web-2', [...hardened(), 'ssh' => ['password_authentication' => true, 'permit_root_login' => 'yes']], [
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 6379, 'exe' => '/usr/bin/redis-server', 'pid' => 4],
    ], ['backend' => 'ufw', 'installed' => true, 'active' => true, 'ports' => [['port' => 6379, 'proto' => 'tcp', 'exposure' => 'open']]]);
    postureMachine(Workspace::factory()->create(), 'elsewhere', hardened());
    $member = User::factory()->create();
    $workspace->members()->attach($member, ['role' => 'member']);

    $this->actingAs($member)->get('https://'.$workspace->host().'/security')->assertOk()->assertInertia(fn (Assert $page) => $page
        ->component('workspace/Security')
        ->has('machines', 2)
        ->where('machines.0.name', 'web-1')
        ->where('machines.0.score', 100)
        ->where('machines.0.policy', 'Default')
        ->where('machines.1.score', 76)
        ->where('machines.1.state', 'scored')
        ->where('summary.average', 88)
        ->where('summary.serious', 1)
        ->where('summary.scored', 2)
    );
});

test('only members who can manage machines see the Security page', function () {
    $workspace = Workspace::factory()->create();
    postureMachine($workspace, 'web-1', hardened());
    $viewer = User::factory()->create();
    $workspace->members()->attach($viewer, ['role' => 'viewer']);

    $this->actingAs($viewer)->get('https://'.$workspace->host().'/security')->assertForbidden();
    $this->actingAs(User::factory()->create())->get('https://'.$workspace->host().'/security')->assertForbidden();
});

test('the Security page names the policy that turned security watch off', function () {
    $workspace = Workspace::factory()->create();
    postureMachine($workspace, 'quiet-1', hardened());
    MachinePolicies::defaultFor($workspace)->update(['security_watch' => false, 'name' => 'Hosting']);

    $this->actingAs($workspace->owner)->get('https://'.$workspace->host().'/security')->assertOk()->assertInertia(fn (Assert $page) => $page
        ->where('machines.0.state', 'watch_off')
        ->where('machines.0.policy', 'Hosting')
        ->where('summary.scored', 0)
    );
});

test('keyboard-interactive sign-in through PAM counts as password sign-in', function () {
    $ssh = fn (bool $keyboard, bool $pam) => [...hardened(), 'ssh' => [...hardened()['ssh'], 'kbd_interactive_authentication' => $keyboard, 'use_pam' => $pam]];

    expect(postureChecks(Posture::report(postureMachine(Workspace::factory()->create(), 'a', $ssh(true, true))))['ssh_password']['status'])->toBe('fail')
        ->and(postureChecks(Posture::report(postureMachine(Workspace::factory()->create(), 'b', $ssh(true, false))))['ssh_password']['status'])->toBe('pass');
});

test('the firewall default only counts when the firewall is on', function () {
    $firewall = fn (bool $active, string $incoming) => ['backend' => 'ufw', 'installed' => true, 'active' => $active, 'default_incoming' => $incoming, 'ports' => []];

    expect(postureChecks(Posture::report(postureMachine(Workspace::factory()->create(), 'a', hardened(), [], $firewall(true, 'allow'))))['firewall_default']['status'])->toBe('fail')
        ->and(postureChecks(Posture::report(postureMachine(Workspace::factory()->create(), 'b', hardened(), [], $firewall(true, 'deny'))))['firewall_default']['status'])->toBe('pass')
        ->and(postureChecks(Posture::report(postureMachine(Workspace::factory()->create(), 'c', hardened(), [], $firewall(false, 'allow'))))['firewall_default']['status'])->toBe('unknown');
});

test('a database published by Docker counts once, as exposed', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'docker-1', hardened(), [
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 6379, 'exe' => '/usr/bin/docker-proxy', 'pid' => 5, 'cmdline' => 'redis-server *:6379'],
    ], ['backend' => 'ufw', 'installed' => true, 'active' => true, 'default_incoming' => 'deny', 'ports' => [['port' => 6379, 'proto' => 'tcp', 'exposure' => 'docker']]]);

    $checks = postureChecks(Posture::report($machine));

    expect($checks['exposed']['status'])->toBe('fail')
        ->and($checks['docker_ports']['status'])->toBe('pass');
});

test('Docker ports skip web ports and ServerOS’s own, and only count with a firewall on', function () {
    $listeners = [
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 443, 'exe' => '/usr/bin/docker-proxy', 'pid' => 5],
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 8443, 'exe' => '/usr/bin/docker-proxy', 'pid' => 6],
        ['proto' => 'tcp', 'address' => '0.0.0.0', 'port' => 2456, 'exe' => '/usr/bin/docker-proxy', 'pid' => 7],
    ];
    $firewall = fn (bool $active) => ['backend' => 'ufw', 'installed' => true, 'active' => $active, 'default_incoming' => 'deny', 'ports' => [
        ['port' => 443, 'proto' => 'tcp', 'exposure' => 'docker'],
        ['port' => 8443, 'proto' => 'tcp', 'exposure' => 'docker'],
        ['port' => 2456, 'proto' => 'tcp', 'exposure' => 'docker'],
    ]];
    $machine = postureMachine(Workspace::factory()->create(), 'panel-1', hardened(), $listeners, $firewall(true));
    $machine->forceFill(['inventory' => [...$machine->inventory, 'services' => [
        ['key' => 'docker:abc', 'name' => 'serveros-gateway-1', 'ports' => [8443], 'details' => ['image' => 'ghcr.io/serveroshq/panel:latest']],
    ]]])->save();

    $checks = postureChecks(Posture::report($machine));
    expect($checks['docker_ports']['status'])->toBe('fail')
        ->and($checks['docker_ports']['params']['ports'])->toBe('2456/tcp');

    $off = postureMachine(Workspace::factory()->create(), 'open-1', hardened(), $listeners, $firewall(false));
    expect(postureChecks(Posture::report($off))['docker_ports']['status'])->toBe('unknown');
});

test('a renewed certificate doesn’t count its old copy as expired', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'tls-1', hardened());
    $machine->forceFill(['inventory' => [...$machine->inventory, 'certificates' => [
        ['path' => '/etc/letsencrypt/archive/a/cert1.pem', 'not_after' => now()->subDays(30)->getTimestamp(), 'names' => ['a.example.com']],
        ['path' => '/etc/letsencrypt/archive/a/cert2.pem', 'not_after' => now()->addDays(60)->getTimestamp(), 'names' => ['a.example.com']],
    ]]])->save();

    $checks = postureChecks(Posture::report($machine));
    expect($checks['certificate_expired']['status'])->toBe('pass')
        ->and($checks['certificate_expiring']['status'])->toBe('pass');
});

test('an older daemon than the newest release fails, and no releases is unknown', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'old-1', hardened(), attributes: ['daemon_version' => 'v0.1.1-pre.30']);
    $machine->forceFill(['facts' => [...$machine->facts, 'arch' => 'x86_64']])->save();

    expect(postureChecks(Posture::report($machine))['daemon']['status'])->toBe('unknown');

    DaemonRelease::query()->create(['version' => 'v0.1.1-pre.38', 'arch' => 'amd64', 'channel' => 'stable', 'sha256' => str_repeat('a', 64), 'signature' => 'sig']);
    $checks = postureChecks(Posture::report($machine->fresh()));

    expect($checks['daemon']['status'])->toBe('fail')
        ->and($checks['daemon']['params'])->toBe(['installed' => 'v0.1.1-pre.30', 'latest' => 'v0.1.1-pre.38']);

    $machine->forceFill(['daemon_version' => 'v0.1.1-pre.38'])->save();
    expect(postureChecks(Posture::report($machine->fresh()))['daemon']['status'])->toBe('pass');
});

test('CVE checks count open vulnerabilities only, and leave the score alone when the CVE watcher is off', function () {
    $machine = postureMachine(Workspace::factory()->create(), 'cve-1', hardened());
    postureCve($machine, 'CVE-2026-0003', 'medium');
    postureCve($machine, 'CVE-2026-0004', 'critical', resolved: true);

    $checks = postureChecks(Posture::report($machine));
    expect($checks['exploited']['status'])->toBe('pass')
        ->and($checks['cves']['status'])->toBe('pass');

    foreach (range(5, 9) as $n) {
        postureCve($machine, "CVE-2026-000{$n}", 'high');
    }
    expect(postureChecks(Posture::report($machine->fresh()))['cves']['params'])->toBe(['cves' => 'CVE-2026-0005, CVE-2026-0006, CVE-2026-0007', 'more' => 2]);

    $machine->forceFill(['vulns_scanned_at' => null])->save();
    expect(Posture::report($machine->fresh())['state'])->toBe('incomplete');

    config(['security.cves.enabled' => false]);
    $report = Posture::report($machine->fresh());
    expect($report['state'])->toBe('scored')
        ->and(postureChecks($report))->not->toHaveKey('exploited');
});
