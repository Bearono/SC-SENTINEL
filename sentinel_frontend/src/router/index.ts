import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: () => import('@/views/HomeView.vue'),
      meta: { title: 'SENTINEL | 上传审计' }
    },
    {
      path: '/tasks',
      name: 'tasks',
      component: () => import('@/views/TaskListView.vue'),
      meta: { title: 'SENTINEL | 任务列表' }
    },
    {
      path: '/tasks/:id/report',
      name: 'report',
      component: () => import('@/views/ReportView.vue'),
      meta: { title: 'SENTINEL | 审计报告' }
    },
    {
      path: '/about',
      name: 'about',
      component: () => import('@/views/AboutView.vue'),
      meta: { title: 'SENTINEL | 关于' }
    },
    // 404 回退
    {
      path: '/:pathMatch(.*)*',
      redirect: '/'
    }
  ],
  scrollBehavior(_to, _from, savedPosition) {
    if (savedPosition) return savedPosition
    return { top: 0, behavior: 'smooth' }
  }
})

// 更新页面标题
router.afterEach((to) => {
  if (to.meta.title) {
    document.title = to.meta.title as string
  }
})

export default router
