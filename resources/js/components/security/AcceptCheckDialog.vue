<script setup lang="ts">
import { useForm } from '@inertiajs/vue3';
import { watch } from 'vue';
import InputError from '@/components/InputError.vue';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import AppButton from '@/components/workspace/AppButton.vue';
import SubmitButton from '@/components/workspace/SubmitButton.vue';

const props = defineProps<{
    machineId: number;
    machineName: string;
    check: string;
    label: string;
}>();
const open = defineModel<boolean>('open', { default: false });

const form = useForm({ check: '', reason: '', days: 90 });

watch(
    open,
    (value) => {
        if (value) {
            form.reset();
            form.clearErrors();
            form.check = props.check;
        }
    },
    { immediate: true },
);

function submit(): void {
    form.post(`/security/machines/${props.machineId}/accepted`, {
        preserveScroll: true,
        onSuccess: () => (open.value = false),
    });
}
</script>

<template>
    <Dialog v-model:open="open">
        <DialogContent
            class="workspace-panel ds-modal gap-0 overflow-hidden p-0 font-ui text-foreground sm:max-w-md"
        >
            <form class="flex flex-col" @submit.prevent="submit">
                <div class="flex flex-col gap-1 px-5 pt-5">
                    <DialogTitle class="text-base/6 font-semibold">
                        {{
                            $t('Accept :check on :machine', {
                                check: label,
                                machine: machineName,
                            })
                        }}
                    </DialogTitle>
                    <DialogDescription
                        class="text-[13px]/5 text-(--ds-text-muted)"
                    >
                        {{
                            $t(
                                'It stops counting against the score until it expires, or until what fails changes. Everyone who can manage machines sees who accepted it and why.',
                            )
                        }}
                    </DialogDescription>
                </div>

                <div class="flex flex-col gap-5 p-5">
                    <label class="flex flex-col gap-1.5">
                        <span
                            class="text-[13px]/5 font-medium text-(--ds-text-muted)"
                            >{{ $t('Why') }}</span
                        >
                        <Input
                            v-model="form.reason"
                            maxlength="300"
                            required
                            :placeholder="
                                $t('Game server ports, meant to be public')
                            "
                        />
                        <InputError
                            :message="form.errors.reason ?? form.errors.check"
                        />
                    </label>

                    <div class="flex flex-col gap-1.5">
                        <span
                            class="text-[13px]/5 font-medium text-(--ds-text-muted)"
                            >{{ $t('For') }}</span
                        >
                        <div
                            class="ds-segments self-start"
                            role="group"
                            :aria-label="$t('For how long')"
                        >
                            <button
                                v-for="days in [30, 90, 180]"
                                :key="days"
                                type="button"
                                class="cursor-pointer whitespace-nowrap"
                                :aria-pressed="form.days === days"
                                @click="form.days = days"
                            >
                                {{ $t(':count days', { count: String(days) }) }}
                            </button>
                        </div>
                        <InputError :message="form.errors.days" />
                    </div>
                </div>

                <div
                    class="flex items-center gap-2 border-t border-(--ds-border) px-4 py-3"
                >
                    <span class="grow" />
                    <AppButton
                        size="sm"
                        variant="quiet"
                        @click="open = false"
                        >{{ $t('Cancel') }}</AppButton
                    >
                    <SubmitButton
                        :label="$t('Accept')"
                        :busy-label="$t('Accepting…')"
                        :processing="form.processing"
                    />
                </div>
            </form>
        </DialogContent>
    </Dialog>
</template>
