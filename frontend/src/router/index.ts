import { createRouter, createWebHashHistory } from 'vue-router'
import ScanReportView from '@/views/ScanReportView.vue'
import TransitiveDependenciesView from '@/views/TransitiveDependenciesView.vue'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/',
      name: 'scan-report',
      component: ScanReportView,
    },
    {
      path: '/transitive-dependencies',
      name: 'transitive-dependencies',
      component: TransitiveDependenciesView,
    },
  ],
})

export default router
