<script setup lang="ts">
import { trans } from 'laravel-vue-i18n';
import { Head, Link, usePage } from '@inertiajs/vue3';
import { ChevronDown } from '@lucide/vue';
import { computed, ref } from 'vue';
import WorkspacePage from '@/components/workspace/WorkspacePage.vue';
import { onWorkspace } from '@/lib/workspaceRoute';
import machinesRoutes from '@/routes/workspace/machines';
import type { Workspace } from '@/types';

type Severity = 'critical' | 'high' | 'medium' | 'low';

type Check = {
    key: string;
    severity: Severity;
    status: 'pass' | 'fail' | 'unknown';
    params: Record<string, string | number>;
};

type Machine = {
    id: number;
    name: string;
    online: boolean;
    policy: string;
    state: 'scored' | 'incomplete' | 'watch_off' | 'stale' | 'waiting';
    seenAt: string | null;
    score: number | null;
    grade: string | null;
    checks: Check[];
};

type Filter = 'all' | 'attention' | 'passing';

const props = defineProps<{
    workspace: Workspace;
    machines: Machine[];
    summary: {
        machines: number;
        scored: number;
        average: number | null;
        serious: number;
    };
}>();

const focusRing =
    'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--ds-ring)';

const page = usePage();
const filter = ref<Filter>('all');
const linked = Number(
    new URLSearchParams(page.url.split('?')[1] ?? '').get('machine'),
);
const open = ref<number | null>(
    props.machines.some((machine) => machine.id === linked) ? linked : null,
);

const copy: Record<string, { label: string; fail: string; fix: string }> = {
    ssh_password: {
        label: 'SSH password sign-in',
        fail: 'Password sign-in is on',
        fix: 'Once key sign-in works, put PasswordAuthentication no and KbdInteractiveAuthentication no in /etc/ssh/sshd_config.d/00-hardening.conf, so it loads before other files there, then reload sshd.',
    },
    ssh_root: {
        label: 'SSH root sign-in',
        fail: 'Root can sign in over SSH with a password',
        fix: 'Set PermitRootLogin prohibit-password, or no if nobody needs root over SSH, then reload sshd.',
    },
    sign_ins: {
        label: 'Failed sign-ins',
        fail: ':failed failed SSH connections from :sources addresses in the last :minutes minutes',
        fix: 'Turn off password sign-in and allow SSH only from addresses you use, or add fail2ban.',
    },
    exposed: {
        label: 'Databases on the internet',
        fail: 'Open to the internet: :services',
        fix: 'Make them listen on 127.0.0.1 or a private network, or close the ports on the Ports tab.',
    },
    cleartext: {
        label: 'Unencrypted remote access',
        fail: 'Listening: :services',
        fix: 'Turn off Telnet, FTP and the r-services, and use SSH or SFTP.',
    },
    firewall: {
        label: 'Firewall',
        fail: 'No firewall is on',
        fix: 'Turn on ufw or firewalld, and allow SSH first so you keep access.',
    },
    security_updates: {
        label: 'Security updates',
        fail: ':count waiting',
        fix: 'Install them from the Updates tab.',
    },
    auto_updates: {
        label: 'Automatic updates',
        fail: 'Automatic security updates are off',
        fix: 'Debian and Ubuntu: install unattended-upgrades, then run dpkg-reconfigure -plow unattended-upgrades. RHEL family: install dnf-automatic and enable dnf-automatic-install.timer.',
    },
    reboot: {
        label: 'Reboot',
        fail: 'Needed to finish installing updates',
        fix: 'Reboot when it suits you, so the patched kernel and libraries load.',
    },
};

const severityLabel: Record<Severity, string> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
};

const severityTone: Record<Severity, string> = {
    critical: 'text-(--ds-red)',
    high: 'text-(--ds-red)',
    medium: 'text-(--ds-amber)',
    low: 'text-(--ds-text-muted)',
};

function failing(machine: Machine): Check[] {
    return machine.checks.filter((check) => check.status === 'fail');
}

function needsAttention(machine: Machine): boolean {
    if (['incomplete', 'watch_off', 'stale'].includes(machine.state))
        return true;
    if (machine.score !== null && machine.score < 90) return true;

    return failing(machine).some((check) =>
        ['critical', 'high'].includes(check.severity),
    );
}

function isPassing(machine: Machine): boolean {
    return machine.state === 'scored' && !needsAttention(machine);
}

const stateLabel: Record<Machine['state'], string> = {
    scored: '',
    incomplete: 'Incomplete',
    watch_off: 'Checks off',
    stale: 'Stale',
    waiting: '-',
};

const stateDetail: Record<Machine['state'], string> = {
    scored: 'No issues found',
    incomplete: 'Not enough data to score yet',
    watch_off: 'Security checks are off in its policy',
    stale: 'No report for over a day',
    waiting: 'Waiting for the first report',
};

function params(check: Check): Record<string, string> {
    return Object.fromEntries(
        Object.entries(check.params).map(([key, value]) => [
            key,
            String(value),
        ]),
    );
}

function detail(check: Check): string {
    if (check.status !== 'fail') return '';

    return trans(copy[check.key]?.fail ?? check.key, params(check));
}

function scoreTone(score: number | null): string {
    if (score === null) return 'text-(--ds-text-faint)';
    if (score >= 90) return 'text-(--ds-green)';
    if (score >= 70) return 'text-(--ds-amber)';

    return 'text-(--ds-red)';
}

const counts = computed(() => ({
    all: props.machines.length,
    attention: props.machines.filter(needsAttention).length,
    passing: props.machines.filter(isPassing).length,
}));

const tabs = computed(() => [
    { value: 'all' as const, label: trans('All'), count: counts.value.all },
    {
        value: 'attention' as const,
        label: trans('Needs attention'),
        count: counts.value.attention,
    },
    {
        value: 'passing' as const,
        label: trans('Passing'),
        count: counts.value.passing,
    },
]);

const rows = computed(() =>
    props.machines
        .filter((machine) => {
            if (filter.value === 'attention') return needsAttention(machine);
            if (filter.value === 'passing') return isPassing(machine);

            return true;
        })
        .sort((a, b) => (a.score ?? 101) - (b.score ?? 101)),
);

const columns = {
    machine: 'w-64 shrink-0',
    score: 'w-24 shrink-0',
    issues: 'w-20 shrink-0',
    top: 'min-w-64 flex-1',
};

function settingsHref(machine: Machine) {
    return onWorkspace(
        machinesRoutes.settings({
            workspace: props.workspace.slug,
            machine: machine.id,
        }),
    );
}

function machineHref(machine: Machine) {
    return onWorkspace(
        machinesRoutes.show({
            workspace: props.workspace.slug,
            machine: machine.id,
        }),
    );
}
</script>

<template>
    <Head :title="$t('Security')" />

    <WorkspacePage :title="$t('Security')">
        <template #description>
            {{
                ' ' +
                $t(
                    'A score for each machine from its SSH settings, sign-ins, open ports and updates, with what to change.',
                ) +
                ' '
            }}
        </template>

        <template v-if="machines.length > 0" #tabs>
            <div class="max-w-full overflow-x-auto">
                <div
                    class="ds-segments"
                    role="group"
                    :aria-label="$t('Filter machines')"
                >
                    <button
                        v-for="tab in tabs"
                        :key="tab.value"
                        type="button"
                        class="cursor-pointer gap-1.5"
                        :class="focusRing"
                        :aria-pressed="filter === tab.value"
                        @click="filter = tab.value"
                    >
                        {{ tab.label }}
                        <span
                            class="text-xs/4 text-(--ds-text-muted) tabular-nums"
                        >
                            {{ tab.count }}
                        </span>
                    </button>
                </div>
            </div>
        </template>

        <div
            v-if="machines.length > 0"
            class="flex flex-wrap gap-6 font-ui text-[13px]/5 text-(--ds-text-secondary)"
        >
            <span>
                {{ $t('Average score') }}
                <span
                    class="ml-1 font-medium tabular-nums"
                    :class="scoreTone(summary.average)"
                    >{{ summary.average ?? '-' }}</span
                >
            </span>
            <span>
                {{ $t('Machines with critical or high issues') }}
                <span class="ml-1 font-medium text-(--ds-text) tabular-nums">{{
                    summary.serious
                }}</span>
            </span>
            <span>
                {{ $t('Machines scored') }}
                <span class="ml-1 font-medium text-(--ds-text) tabular-nums"
                    >{{ summary.scored }} / {{ summary.machines }}</span
                >
            </span>
        </div>

        <div
            v-if="machines.length > 0"
            class="ds-tile shrink-0 overflow-x-auto"
            role="table"
            :aria-label="$t('Security')"
        >
            <div class="flex w-full min-w-max flex-col">
                <div
                    class="ds-tile-head flex h-9.5 items-center border-b border-(--ds-divider) px-4 font-ui text-xs/4 font-medium text-(--ds-text-muted)"
                    role="row"
                >
                    <span :class="columns.machine" role="columnheader">{{
                        $t('Machine')
                    }}</span>
                    <span :class="columns.score" role="columnheader">{{
                        $t('Score')
                    }}</span>
                    <span :class="columns.issues" role="columnheader">{{
                        $t('Issues')
                    }}</span>
                    <span :class="columns.top" role="columnheader">{{
                        $t('Top issue')
                    }}</span>
                </div>

                <template v-for="machine in rows" :key="machine.id">
                    <div
                        class="flex h-13 cursor-pointer items-center border-b border-(--ds-divider) px-4 font-ui text-[13px]/4 transition-colors last:border-b-0 hover:bg-(--ds-row-hover)"
                        :class="focusRing"
                        role="row"
                        tabindex="0"
                        :aria-expanded="open === machine.id"
                        @click="open = open === machine.id ? null : machine.id"
                        @keydown.enter.self="
                            open = open === machine.id ? null : machine.id
                        "
                    >
                        <div
                            :class="columns.machine"
                            class="flex items-center gap-2"
                            role="cell"
                        >
                            <ChevronDown
                                class="size-3 shrink-0 text-(--ds-text-muted) transition-transform"
                                :class="{ '-rotate-90': open !== machine.id }"
                                :stroke-width="2"
                            />
                            <span
                                class="truncate font-medium text-(--ds-text)"
                                >{{ machine.name }}</span
                            >
                            <span
                                v-if="!machine.online"
                                class="text-xs text-(--ds-text-faint)"
                                >{{ $t('Offline') }}</span
                            >
                        </div>
                        <div
                            :class="[columns.score, scoreTone(machine.score)]"
                            class="font-medium tabular-nums"
                            role="cell"
                        >
                            <template v-if="machine.score !== null">
                                {{ machine.score }}
                                <span class="ml-1 text-(--ds-text-muted)">{{
                                    machine.grade
                                }}</span>
                            </template>
                            <span v-else class="text-(--ds-text-muted)">{{
                                $t(stateLabel[machine.state])
                            }}</span>
                        </div>
                        <div
                            :class="columns.issues"
                            class="text-(--ds-text) tabular-nums"
                            role="cell"
                        >
                            {{ failing(machine).length }}
                        </div>
                        <div
                            :class="columns.top"
                            class="truncate text-(--ds-text-secondary)"
                            role="cell"
                        >
                            <template
                                v-if="
                                    ['stale', 'waiting', 'watch_off'].includes(
                                        machine.state,
                                    )
                                "
                                >{{ $t(stateDetail[machine.state]) }}</template
                            >
                            <template v-else-if="failing(machine).length">
                                <span
                                    class="mr-1.5 font-medium"
                                    :class="
                                        severityTone[
                                            failing(machine)[0].severity
                                        ]
                                    "
                                    >{{
                                        $t(
                                            severityLabel[
                                                failing(machine)[0].severity
                                            ],
                                        )
                                    }}</span
                                >
                                {{ detail(failing(machine)[0]) }}
                            </template>
                            <template v-else>{{
                                $t(stateDetail[machine.state])
                            }}</template>
                        </div>
                    </div>

                    <div
                        v-if="open === machine.id"
                        class="flex flex-col gap-1 border-b border-(--ds-divider) bg-(--ds-subtle)/40 px-4 py-3 pl-9 font-ui text-[13px]/5"
                        role="rowgroup"
                    >
                        <p
                            v-if="machine.state === 'watch_off'"
                            class="max-w-[68rem] pb-1.5 text-(--ds-text-secondary)"
                        >
                            {{
                                $t(
                                    'Security checks are off in :policy, so SSH settings, sign-ins and automatic updates aren’t read. Turn them on in that policy, or pick another policy in the machine’s settings.',
                                    { policy: machine.policy },
                                )
                            }}
                            <Link
                                :href="settingsHref(machine)"
                                class="font-medium text-(--ds-blue) hover:underline hover:underline-offset-4"
                                :class="focusRing"
                                >{{ $t('Machine settings') }}</Link
                            >
                        </p>
                        <div
                            v-for="check in machine.checks"
                            :key="check.key"
                            class="grid grid-cols-[5rem_15rem_minmax(0,46rem)] gap-x-4 gap-y-0.5 py-1.5"
                            role="row"
                        >
                            <span
                                class="font-medium"
                                :class="
                                    check.status === 'fail'
                                        ? severityTone[check.severity]
                                        : check.status === 'pass'
                                          ? 'text-(--ds-green)'
                                          : 'text-(--ds-text-faint)'
                                "
                                role="cell"
                                >{{
                                    check.status === 'fail'
                                        ? $t(severityLabel[check.severity])
                                        : check.status === 'pass'
                                          ? $t('Passed')
                                          : $t('Unknown')
                                }}</span
                            >
                            <span class="text-(--ds-text)" role="cell">
                                {{ $t(copy[check.key]?.label ?? check.key) }}
                            </span>
                            <span
                                class="text-(--ds-text-secondary)"
                                role="cell"
                                >{{ detail(check) }}</span
                            >
                            <span
                                v-if="
                                    check.status === 'fail' && copy[check.key]
                                "
                                class="col-start-3 text-(--ds-text-muted)"
                                role="cell"
                            >
                                {{ $t(copy[check.key].fix) }}
                            </span>
                        </div>
                        <Link
                            :href="machineHref(machine)"
                            class="mt-1 self-start font-medium text-(--ds-blue) hover:underline hover:underline-offset-4"
                            :class="focusRing"
                        >
                            {{ $t('Open machine') }}
                        </Link>
                    </div>
                </template>
            </div>
        </div>

        <div
            v-else
            class="flex flex-col items-start gap-1 rounded-xl border border-(--ds-border) px-5 py-6 font-ui text-[13px]/5"
        >
            <span class="font-medium text-(--ds-text)">{{
                $t('No machines yet')
            }}</span>
            <span class="text-(--ds-text-secondary)">{{
                $t('Connect a machine to see its security score.')
            }}</span>
        </div>
    </WorkspacePage>
</template>
