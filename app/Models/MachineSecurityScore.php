<?php

namespace App\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property int $id
 * @property int $machine_id
 * @property CarbonImmutable $date
 * @property string $state
 * @property int|null $score
 * @property list<string> $failing
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 */
#[Fillable(['machine_id', 'date', 'state', 'score', 'failing'])]
class MachineSecurityScore extends Model
{
    public const KEEP_DAYS = 180;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['date' => 'immutable_date', 'failing' => 'array'];
    }

    /** @return BelongsTo<Machine, $this> */
    public function machine(): BelongsTo
    {
        return $this->belongsTo(Machine::class);
    }
}
