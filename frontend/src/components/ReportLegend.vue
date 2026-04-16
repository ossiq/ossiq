<script setup lang="ts">
import { constraintCircleClasses } from '@/explorer/nodeStyle'
</script>

<template>
  <section class="mb-6">
    <div class="border border-slate-200 border-b-[3px] border-b-slate-300 bg-white p-6">
      <h2 class="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-4">Legend</h2>

      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        <!-- Major Drift -->
        <div class="flex items-start gap-3">
          <span class="block w-3 h-3 mt-1 rounded-full bg-red-500 shrink-0"></span>
          <div>
            <div class="text-sm font-bold text-slate-900">Drift Status: MAJOR</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              One or more major versions behind, implying accumulated breaking changes and higher remediation effort.
            </p>
          </div>
        </div>

        <!-- Minor Drift -->
        <div class="flex items-start gap-3">
          <span class="block w-3 h-3 mt-1 rounded-full bg-amber-500 shrink-0"></span>
          <div>
            <div class="text-sm font-bold text-slate-900">Drift Status: MINOR</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              Behind on non-breaking feature releases; remediation is typically low-risk.
            </p>
          </div>
        </div>

        <!-- Patch Drift -->
        <div class="flex items-start gap-3">
          <span class="block w-3 h-3 mt-1 rounded-full bg-blue-500 shrink-0"></span>
          <div>
            <div class="text-sm font-bold text-slate-900">Drift Status: PATCH</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              Missing bugfixes or security patches; remediation effort is usually minimal.
            </p>
          </div>
        </div>

        <!-- Latest -->
        <div class="flex items-start gap-3">
          <span class="block w-3 h-3 mt-1 rounded-full bg-emerald-500 shrink-0"></span>
          <div>
            <div class="text-sm font-bold text-slate-900">Drift Status: LATEST</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              Aligned with the latest release; no remediation required.
            </p>
          </div>
        </div>

        <!-- Release Distance -->
        <div class="flex items-start gap-3">
          <span class="material-symbols-rounded text-lg text-slate-400 shrink-0">stacks</span>
          <div>
            <div class="text-sm font-bold text-slate-900">Release Distance</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              The number of releases between the installed version and the latest available version.
            </p>
          </div>
        </div>

        <!-- Time Lag -->
        <div class="flex items-start gap-3">
          <span class="material-symbols-rounded text-lg text-slate-400 shrink-0">change_history</span>
          <div>
            <div class="text-sm font-bold text-slate-900">Time Lag</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              Time elapsed between installed and latest release.
              <span class="text-emerald-500">Green</span>: &lt;365 days,
              <span class="text-amber-500">Orange</span>: &gt;365 days,
              <span class="text-red-500">Red</span>: &gt;730 days.
            </p>
          </div>
        </div>

        <!-- Transitive CVE -->
        <div class="flex items-start gap-3">
          <span class="text-orange-500 font-black text-lg shrink-0 leading-none mt-0.5">*</span>
          <div>
            <div class="text-sm font-bold text-slate-900">Transitive CVE</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              One or more transitive (indirect) dependencies of this package have known CVEs.
            </p>
          </div>
        </div>

        <!-- Constrained: NARROWED -->
        <div class="flex items-start gap-3">
          <span class="block w-5 h-5 mt-0.5 rounded-full shrink-0" :class="constraintCircleClasses('NARROWED')"></span>
          <div>
            <div class="text-sm font-bold text-slate-900">Constrained: NARROWED</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              Version range explicitly bounded (e.g. <code class="font-mono">&gt;=x &lt;y</code>,
              <code class="font-mono">~=x</code>, <code class="font-mono">==x.*</code>); resolver has less flexibility.
            </p>
          </div>
        </div>

        <!-- Constrained: PINNED -->
        <div class="flex items-start gap-3">
          <span class="block w-5 h-5 mt-0.5 rounded-full shrink-0" :class="constraintCircleClasses('PINNED')"></span>
          <div>
            <div class="text-sm font-bold text-slate-900">Constrained: PINNED</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              Exact version required (<code class="font-mono">==x.y.z</code> or bare <code class="font-mono">x.y.z</code>);
              no resolution flexibility.
            </p>
          </div>
        </div>

        <!-- Constrained: ADDITIVE -->
        <div class="flex items-start gap-3">
          <span class="block w-5 h-5 mt-0.5 rounded-full shrink-0" :class="constraintCircleClasses('ADDITIVE')"></span>
          <div>
            <div class="text-sm font-bold text-slate-900">Constrained: ADDITIVE</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              Version range narrowed by an external constraint file (pip <code class="font-mono">-c</code>,
              uv <code class="font-mono">constraint-dependencies</code>) without adding a direct dependency.
            </p>
          </div>
        </div>

        <!-- Constrained: OVERRIDE -->
        <div class="flex items-start gap-3">
          <span class="block w-5 h-5 mt-0.5 rounded-full shrink-0" :class="constraintCircleClasses('OVERRIDE')"></span>
          <div>
            <div class="text-sm font-bold text-slate-900">Constrained: OVERRIDE</div>
            <p class="text-xs text-slate-500 leading-relaxed">
              Version forcibly replaced by an override directive (npm <code class="font-mono">overrides</code>,
              uv <code class="font-mono">override-dependencies</code>), bypassing normal resolution constraints.
            </p>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
