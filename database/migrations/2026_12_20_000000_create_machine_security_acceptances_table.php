<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('machine_security_acceptances', function (Blueprint $table) {
            $table->id();
            $table->foreignId('machine_id')->constrained()->cascadeOnDelete();
            $table->string('check', 40);
            $table->string('fingerprint', 40);
            $table->string('reason', 300);
            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();
            $table->timestamp('expires_at');
            $table->timestamps();
            $table->unique(['machine_id', 'check']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('machine_security_acceptances');
    }
};
