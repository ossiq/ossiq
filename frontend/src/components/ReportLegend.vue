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
      </div>
    </div>
  </section>
</template>
